// ─── Sentry Error Monitoring ──────────────────────────────
// MUST be the first require — captures errors from all subsequent modules
const { Sentry } = require('./sentry');

const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');
const https = require('https');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const OpenAI = require('openai');
const PDFDocument = require('pdfkit');
const { startNotificationScheduler, sendUnusualTransactionAlert } = require('./notifications');
const { createCheckoutSession, verifyCheckoutSession, PLANS: STRIPE_PLANS, getStripe } = require('./services/stripe-direct');
const { sendInvoiceEmail, sendInviteEmail, sendEmail, sendAuthEmail, sendWelcomeEmail, wrapHtml } = require('./email');

const app = express();
const port = process.env.PORT || 3000;
app.get('/healthz', (req, res) => {
  res.status(200).send('ok');
});
const GA_MEASUREMENT_ID = process.env.GA_MEASUREMENT_ID || 'G-0CKFPZFEPR';

// ─── Custom Domain Redirect ─────────────────────────────
// Redirect old finowl.polsia.app → finowl.co.uk so old links keep working
// Note: finowl.co.uk and www.finowl.co.uk are both registered custom domains on Render
// and serve the app directly — no redirect needed for those
const CUSTOM_DOMAIN_REDIRECT = 'https://finowl.co.uk';
app.use((req, res, next) => {
  const host = req.get('Host') || '';
  if (host === 'finowl.polsia.app') {
    const target = CUSTOM_DOMAIN_REDIRECT + req.originalUrl;
    return res.redirect(301, target);
  }
  next();
});

// ─── Security Headers (HTTP) ────────────────────────────
// All 6 critical headers from security audit.
// Must come BEFORE any routes so headers apply to every response.
const IS_PROD = !process.env.DATABASE_URL?.includes('localhost');
const SELF_DOMAINS = [
  'https://finowl.co.uk',
  'https://www.finowl.co.uk',
  'https://finowl.polsia.app',
  ...(IS_PROD ? [] : ['http://localhost:3000', 'http://localhost:5173']),
].join(' ');

app.use((req, res, next) => {
  // 1. HSTS — enforce HTTPS for 1 year
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

  // 2. CSP — restrictive policy; allow self + Google Fonts only
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      `script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://cdn.jsdelivr.net`,  // GA4 + inline scripts + Chart.js CDN
      `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`,
      `font-src 'self' https://fonts.gstatic.com`,
      `img-src 'self' data: https://* blob:`,     // R2 and receipts
      `connect-src 'self' https://api.openai.com https://*.openai.com https://*.cloudflarestream.com https://www.google-analytics.com https://www.googletagmanager.com https://analytics.google.com`,
      `frame-src 'none'`,
      `object-src 'none'`,
      `base-uri 'self'`,
      `form-action 'self'`,
    ].join('; ')
  );

  // 3. X-Frame-Options — prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');

  // 4. X-Content-Type-Options — prevent MIME sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // 5. Referrer-Policy — don't leak referrer to third parties
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // 6. Permissions-Policy — deny unnecessary browser APIs
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=()'
  );

  next();
});

// ─── Sentry Error Handler ─────────────────────────────────
// Must be after security headers but before routes so it catches all API errors
app.use((err, req, res, next) => {
  // Log to console as normal
  console.error('[Unhandled Error]', err.message || err, err.stack);

  // Capture with Sentry (if initialised)
  try {
    const { Sentry } = require('./sentry');
    if (Sentry && Sentry.captureException) {
      Sentry.captureException(err, {
        extra: {
          method: req.method,
          path: req.path,
          userId: req.user?.userId,
        },
      });
    }
  } catch (_) {
    // Sentry may not be configured — that's fine
  }

  // Check if this is a browser request (serves HTML pages, not an API)
  const acceptsHtml = req.headers.accept?.includes('text/html');
  const isDev = process.env.NODE_ENV !== 'production';

  if (acceptsHtml) {
    // For browser requests, redirect to friendly error page
    const ref = isDev ? err.message.replace(/\s+/g, '-').slice(0, 60) : `err-${Date.now()}`;
    const status = err.status || 500;
    // Strip status 200 if err middleware incorrectly set it
    res.redirect(status, `/error.html?ref=${encodeURIComponent(ref)}`);
  } else {
    // API: return JSON error
    res.status(err.status || 500).json({
      error: isDev ? err.message : 'Internal server error',
      ...(isDev ? { stack: err.stack } : {}),
    });
  }
});

// ─── Config ─────────────────────────────────────────────
if (!process.env.DATABASE_URL) {
  console.error('ERROR: DATABASE_URL environment variable is required');
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET || crypto.createHash('sha256')
  .update(process.env.POLSIA_API_KEY || 'REDACTED')
  .digest('hex');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false }
});

// Store pool on globalThis so other modules can share the same connection without circular require
globalThis.__finowlPool = pool;

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  baseURL: process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1',
});

// ═══════════════════════════════════════════════════════════
// STRIPE WEBHOOK  — must be registered BEFORE express.json()
// Stripe requires the raw (unparsed) request body for signature verification.
// express.raw() is applied to this route only.
// ═══════════════════════════════════════════════════════════
app.post(
  '/api/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!webhookSecret) {
      console.error('[stripe-webhook] STRIPE_WEBHOOK_SECRET not set — rejecting event');
      return res.status(400).json({ error: 'Webhook not configured' });
    }

    let event;
    try {
      const stripe = getStripe();
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } catch (err) {
      console.error('[stripe-webhook] Signature verification failed:', err.message);
      return res.status(400).json({ error: `Webhook signature error: ${err.message}` });
    }

    console.log(`[stripe-webhook] Received event: ${event.type} (${event.id})`);

    try {
      switch (event.type) {
        // ── Checkout completed — first-time subscription activation ──
        case 'checkout.session.completed': {
          const session = event.data.object;
          const email = session.customer_email || session.customer_details?.email;
          const customerId = session.customer;
          const subscriptionId = session.subscription;
          const plan = session.metadata?.plan || null;
          console.log(`[stripe-webhook] checkout.session.completed — email=${email} plan=${plan} sub=${subscriptionId}`);
          if (email) {
            await pool.query(
              `UPDATE users
               SET subscription_status = 'active',
                   subscribed_at = COALESCE(subscribed_at, NOW()),
                   subscription_plan = COALESCE($2, subscription_plan),
                   stripe_customer_id = COALESCE(stripe_customer_id, $3),
                   stripe_subscription_id = COALESCE(stripe_subscription_id, $4),
                   updated_at = NOW()
               WHERE LOWER(email) = LOWER($1)`,
              [email, plan, customerId, subscriptionId]
            );
          }
          break;
        }

        // ── Invoice paid — confirm ongoing subscription payment ──
        case 'invoice.paid': {
          const invoice = event.data.object;
          const customerId = invoice.customer;
          const subscriptionId = invoice.subscription;
          console.log(`[stripe-webhook] invoice.paid — customer=${customerId} sub=${subscriptionId}`);
          if (customerId) {
            await pool.query(
              `UPDATE users
               SET subscription_status = 'active',
                   stripe_customer_id = COALESCE(stripe_customer_id, $1),
                   stripe_subscription_id = COALESCE(stripe_subscription_id, $2),
                   updated_at = NOW()
               WHERE stripe_customer_id = $1
                  OR LOWER(email) = LOWER($3)`,
              [customerId, subscriptionId, invoice.customer_email || '']
            );
          }
          break;
        }

        // ── Invoice payment failed — flag failed payment ──
        case 'invoice.payment_failed': {
          const invoice = event.data.object;
          const customerId = invoice.customer;
          console.warn(`[stripe-webhook] invoice.payment_failed — customer=${customerId} attempt=${invoice.attempt_count}`);
          if (customerId) {
            await pool.query(
              `UPDATE users
               SET subscription_status = 'payment_failed',
                   updated_at = NOW()
               WHERE stripe_customer_id = $1
                  OR LOWER(email) = LOWER($2)`,
              [customerId, invoice.customer_email || '']
            );
          }
          break;
        }

        // ── Subscription updated — sync plan/status changes ──
        case 'customer.subscription.updated': {
          const sub = event.data.object;
          const customerId = sub.customer;
          const status = sub.status; // active | trialing | past_due | canceled | ...
          const planKey = sub.metadata?.plan || null;
          console.log(`[stripe-webhook] customer.subscription.updated — customer=${customerId} status=${status}`);

          // Map Stripe status to our internal status
          const internalStatus = ['active', 'trialing'].includes(status) ? 'active'
            : status === 'past_due' ? 'payment_failed'
            : status === 'canceled' ? 'cancelled'
            : status;

          await pool.query(
            `UPDATE users
             SET subscription_status = $2,
                 subscription_plan = COALESCE($3, subscription_plan),
                 stripe_subscription_id = COALESCE(stripe_subscription_id, $4),
                 updated_at = NOW()
             WHERE stripe_customer_id = $1`,
            [customerId, internalStatus, planKey, sub.id]
          );
          break;
        }

        // ── Subscription deleted — deactivate and revoke access ──
        case 'customer.subscription.deleted': {
          const sub = event.data.object;
          const customerId = sub.customer;
          console.log(`[stripe-webhook] customer.subscription.deleted — customer=${customerId}`);
          await pool.query(
            `UPDATE users
             SET subscription_status = 'cancelled',
                 updated_at = NOW()
             WHERE stripe_customer_id = $1`,
            [customerId]
          );
          break;
        }

        default:
          console.log(`[stripe-webhook] Unhandled event type: ${event.type}`);
      }
    } catch (handlerErr) {
      console.error(`[stripe-webhook] Handler error for ${event.type}:`, handlerErr.message);
      // Still return 200 so Stripe doesn't retry — log the error internally
    }

    res.json({ received: true });
  }
);

app.use(express.json({ limit: '20mb' }));

// ─── Audit Logger ────────────────────────────────────────
/**
 * Append an immutable entry to audit_log.
 * Fire-and-forget safe: never throws (logs error instead).
 */
async function logAudit({ userId, actionType, entityType, entityId, oldValue, newValue, req: r }) {
  try {
    await pool.query(
      `INSERT INTO audit_log (user_id, action_type, entity_type, entity_id, old_value, new_value, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        userId,
        actionType,
        entityType,
        entityId,
        oldValue != null ? JSON.stringify(oldValue) : null,
        newValue != null ? JSON.stringify(newValue) : null,
        r ? (r.ip || r.connection?.remoteAddress || null) : null,
        r ? (r.headers['user-agent'] || null) : null,
      ]
    );
  } catch (err) {
    console.error('[AuditLog] Failed to write audit entry:', err.message);
  }
}

// ─── HMRC Audit Events (append-only compliance log) ─────
// Writes to audit_events — semantic business events with event_type + details.
// Fire-and-forget: never awaited, never blocks a response.
function logAuditEvent({ userId, eventType, entityType, entityId, details, req: r }) {
  pool.query(
    `INSERT INTO audit_events (user_id, event_type, entity_type, entity_id, details, ip_address, user_agent)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [
      userId,
      eventType,
      entityType || null,
      entityId != null ? parseInt(entityId) || null : null,
      details != null ? JSON.stringify(details) : null,
      r ? (r.ip || r.connection?.remoteAddress || r.socket?.remoteAddress || null) : null,
      r ? (r.headers?.['user-agent'] || null) : null,
    ]
  ).catch(err => console.error('[AuditEvent] Failed to write:', err.message));
}

// ─── Auth Middleware ─────────────────────────────────────
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Accepts token from query string (for OAuth redirects where headers can't be set)
function authenticateTokenFromQuery(req, res, next) {
  const token = req.query.token || (req.headers['authorization'] && req.headers['authorization'].split(' ')[1]);
  if (!token) return res.status(401).send('Authentication required');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send('Invalid or expired token');
  }
}

// ─── Owner-only middleware (blocks accountant read-only role) ────
function requireOwner(req, res, next) {
  if (req.user && req.user.role === 'accountant') {
    return res.status(403).json({ error: 'Accountants have read-only access' });
  }
  next();
}

// ─── Health Check ───────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// ─── Sentry Client Config ──────────────────────────────────
// Returns { dsn, environment } for browser error tracking.
// Only exposes DSN if SENTRY_DSN is configured server-side.
//
app.get('/sentry-client-config', (req, res) => {
  if (!process.env.SENTRY_DSN) {
    return res.json({ dsn: null });
  }
  res.json({
    dsn: process.env.SENTRY_DSN,
    environment: process.env.NODE_ENV === 'production' ? 'production' : 'development',
  });
});

// ─── Static Files with Cache-Control ─────────────────────
//
// Set cache headers based on file type:
//   HTML pages   → no-store (always fetch fresh)
//   Static assets (icons, JS, CSS) → 1-year cache + immutable (safe for content-hashed filenames)
//   Uploads      → 1-hour cache
//
const publicDir = path.join(__dirname, 'public');

// Serve public/ with cache-control based on extension
app.use((req, res, next) => {
  const filePath = path.join(publicDir, req.path);

  // Only handle files that exist (don't block directory requests)
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    return next();
  }

  const ext = path.extname(req.path).toLowerCase();

  if (ext === '.html') {
    // Never cache HTML — must-revalidate ensures users always see fresh content
    res.set('Cache-Control', 'no-store, must-revalidate');
  } else {
    // All other static assets (icons, JS, CSS, manifest, fonts): 1-year cache
    // immutable = safe because content-hashed filenames bust cache on deploy
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
  }

  next();
});

app.use(express.static(publicDir));

const STATIC_CACHE_MAX_AGE = 'public, max-age=31536000, immutable';
const PWA_CACHE_MAX_AGE = 'public, max-age=3600';
const UPLOADS_CACHE_MAX_AGE = 'public, max-age=3600';

function staticWithCache(staticPath, cacheControl) {
  return (req, res, next) => {
    // Let express.static handle the file serving
    const staticMiddleware = express.static(staticPath);
    staticMiddleware(req, res, () => {
      // Only set cache header if response was not already sent (file not found = 404 handled by express)
      if (!res.headersSent) return next();
      // Set cache header on successful static file responses
      if (res.statusCode === 200 || res.statusCode === 304) {
        res.setHeader('Cache-Control', cacheControl);
      }
    });
  };
}

// Static assets with long-term immutable caching
app.use(staticWithCache(path.join(__dirname, 'public'), STATIC_CACHE_MAX_AGE));


// ─── Landing Page ───────────────────────────────────────
app.get('/', (req, res) => {
  const slug = process.env.POLSIA_ANALYTICS_SLUG || '';
  const htmlPath = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(htmlPath)) {
    let html = fs.readFileSync(htmlPath, 'utf8');
    html = html.replace('__POLSIA_SLUG__', slug);
    html = html.replace('__GA_MEASUREMENT_ID__', GA_MEASUREMENT_ID);
    res.type('html').send(html);
  } else {
    res.json({ message: 'FinOwl API' });
  }
});

// ─── App Pages ──────────────────────────────────────────
app.get('/login', (req, res) => {
  const htmlPath = path.join(__dirname, 'public', 'login.html');
  let html = fs.readFileSync(htmlPath, 'utf8');
  html = html.replace('__GA_MEASUREMENT_ID__', GA_MEASUREMENT_ID);
  res.type('html').send(html);
});

app.get('/signup', (req, res) => {
  const htmlPath = path.join(__dirname, 'public', 'signup.html');
  let html = fs.readFileSync(htmlPath, 'utf8');
  html = html.replace('__GA_MEASUREMENT_ID__', GA_MEASUREMENT_ID);
  res.type('html').send(html);
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

app.get('/dashboard', (req, res) => {
  const htmlPath = path.join(__dirname, 'public', 'dashboard.html');
  let html = fs.readFileSync(htmlPath, 'utf8');
  html = html.replace('__GA_MEASUREMENT_ID__', GA_MEASUREMENT_ID);
  // Inject Sentry browser credentials server-side so the SDK initialises
  // synchronously in <head> — before any script block that could throw a
  // parse-time error.  Placeholders are safe to ship in the static HTML file
  // because they're replaced here on every request.
  const sentryDsn = process.env.SENTRY_DSN || '';
  const sentryEnv = process.env.NODE_ENV === 'production' ? 'production' : 'development';
  html = html.replace('__SENTRY_DSN__', sentryDsn);
  html = html.replace('__SENTRY_ENV__', sentryEnv);
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.type('html').send(html);
});

// ─── Legal Pages (clean URLs) ────────────────────────────
app.get('/terms', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'terms.html'));
});

app.get('/privacy', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

app.get('/cookies', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'cookies.html'));
});

app.get('/security', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'security.html'));
});

app.get('/security.txt', (req, res) => {
  res.redirect(301, '/.well-known/security.txt');
});

// ─── SEO Content Pages ───────────────────────────────────
app.get('/mtd-for-vat-software', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'mtd-for-vat-software.html'));
});

app.get('/ai-bookkeeper-uk', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ai-bookkeeper-uk.html'));
});

app.get('/sole-trader-bookkeeping-software', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'sole-trader-bookkeeping-software.html'));
});

// ─── Stripe Checkout Success Page ─────────────────────────
app.get('/checkout/success', (req, res) => {
  const htmlPath = path.join(__dirname, 'public', 'checkout-success.html');
  let html = fs.readFileSync(htmlPath, 'utf8');
  html = html.replace('__GA_MEASUREMENT_ID__', GA_MEASUREMENT_ID);
  res.type('html').send(html);
});

// ─── SEO: robots.txt ────────────────────────────────────
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send([
    'User-agent: *',
    'Allow: /',
    'Disallow: /api/',
    'Disallow: /dashboard',
    '',
    'Sitemap: https://finowl.co.uk/sitemap.xml',
  ].join('\n'));
});

// ─── SEO: sitemap.xml ───────────────────────────────────
// Served as static file from public/sitemap.xml via express.static middleware above.
// Includes all public pages: /, /login, /signup, /reset-password, /terms, /privacy,
// /cookies, /security. robots.txt already references it at https://finowl.co.uk/sitemap.xml

// ═══════════════════════════════════════════════════════════
// AUTH API
// ═══════════════════════════════════════════════════════════

// ─── Password Validation ────────────────────────────────
function validatePassword(password) {
  if (!password || password.length < 8) return 'Password must be at least 8 characters';
  return null;
}

// ─── POST /api/auth/register ────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, confirmPassword } = req.body;

    // Validate inputs
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Valid email address is required' });
    }
    const pwError = validatePassword(password);
    if (pwError) return res.status(400).json({ error: pwError });
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    const normalised = email.toLowerCase().trim();

    // Check if email already registered
    const existing = await pool.query(
      'SELECT id, password_hash FROM users WHERE LOWER(email) = $1',
      [normalised]
    );
    if (existing.rows[0] && existing.rows[0].password_hash) {
      return res.status(409).json({ error: 'An account with this email already exists. Please log in.' });
    }

    // Hash password
    const hash = await bcrypt.hash(password, 12);

    // Generate email verification token
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

    let user;
    if (existing.rows[0]) {
      // User exists (old magic-link account) — set their password, mark unverified until they confirm
      const r = await pool.query(
        `UPDATE users
         SET password_hash = $1,
             email_verified = FALSE,
             email_verification_token = $2,
             email_verification_expires = $3,
             updated_at = NOW(),
             subscription_status = COALESCE(subscription_status, 'trial')
         WHERE id = $4
         RETURNING id, email, name`,
        [hash, token, expires, existing.rows[0].id]
      );
      user = r.rows[0];
    } else {
      // New user
      const r = await pool.query(
        `INSERT INTO users (email, name, password_hash, email_verified, email_verification_token, email_verification_expires, subscription_status)
         VALUES ($1, $2, $3, FALSE, $4, $5, 'trial')
         RETURNING id, email, name`,
        [normalised, normalised.split('@')[0], hash, token, expires]
      );
      user = r.rows[0];
    }

    // Send verification email
    const verifyUrl = `${process.env.APP_URL || 'https://finowl.co.uk'}/api/auth/verify-email?token=${token}`;
    await sendAuthEmail({
      to: normalised,
      subject: 'Verify your FinOwl account',
      htmlBody: `
        <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:520px;margin:32px auto;background:#fff;border-radius:16px;overflow:hidden;border:1px solid #e5e2db;">
          <div style="background:#0a0f1a;padding:20px 28px;display:flex;align-items:center;gap:10px;">
            <span style="background:#d4920b;border-radius:50%;width:34px;height:34px;display:inline-flex;align-items:center;justify-content:center;font-size:16px;">🦉</span>
            <span style="color:#fff;font-size:18px;font-weight:700;letter-spacing:-0.3px;">FinOwl</span>
          </div>
          <div style="padding:28px;">
            <h2 style="font-size:1.3rem;margin-bottom:12px;color:#0a0f1a;">Verify your email address</h2>
            <p style="color:#6b7280;margin-bottom:24px;line-height:1.6;">Almost there! Click the button below to verify your email and activate your FinOwl account.</p>
            <a href="${verifyUrl}" style="display:inline-block;background:#d4920b;color:#fff;padding:12px 28px;border-radius:10px;text-decoration:none;font-weight:600;font-size:1rem;">Verify my email</a>
            <p style="margin-top:20px;color:#9ca3af;font-size:0.85rem;">This link expires in 24 hours. If you didn't sign up for FinOwl, you can ignore this email.</p>
            <hr style="border:none;border-top:1px solid #e5e2db;margin:20px 0;">
            <p style="color:#9ca3af;font-size:0.8rem;">Or copy this link into your browser:<br><span style="word-break:break-all;">${verifyUrl}</span></p>
          </div>
        </div>
      `,
    }).catch(err => console.error('[Auth] Verification email failed:', err.message));

    // Send welcome email too (runs in parallel with verification email)
    sendWelcomeEmail({ to: normalised, name: user.name, email: normalised })
      .catch(err => console.error('[Auth] Welcome email failed:', err.message));

    res.json({ success: true, message: 'Account created. Please check your email to verify your address before logging in.' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// ─── POST /api/auth/login ───────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const normalised = email.toLowerCase().trim();

    const result = await pool.query(
      'SELECT id, email, name, password_hash, email_verified FROM users WHERE LOWER(email) = $1',
      [normalised]
    );
    const user = result.rows[0];

    // Constant-time failure — don't reveal whether email exists
    const dummyHash = '$2a$12$invalid.hash.for.timing.protection.padding.padding';
    const storedHash = user?.password_hash || dummyHash;

    const passwordMatch = await bcrypt.compare(password, storedHash);

    if (!user || !user.password_hash || !passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (!user.email_verified) {
      return res.status(403).json({
        error: 'Please verify your email before logging in. Check your inbox for a verification link.',
        code: 'EMAIL_NOT_VERIFIED',
      });
    }

    const expiresIn = rememberMe ? '30d' : '24h';
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn }
    );

    res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
    try { logAuditEvent({ userId: user.id, eventType: 'user_login', entityType: 'auth', entityId: user.id, details: { email: user.email }, req }); } catch (_) {}
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// ─── Redirect /verify-email → /api/auth/verify-email (safety net for old links)
app.get('/verify-email', (req, res) => {
  const qs = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  res.redirect(301, `/api/auth/verify-email${qs}`);
});

// ─── GET /api/auth/verify-email ─────────────────────────
app.get('/api/auth/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.redirect('/login?error=invalid_token');

    const result = await pool.query(
      `SELECT id, email, name FROM users
       WHERE email_verification_token = $1
         AND email_verification_expires > NOW()`,
      [token]
    );
    const user = result.rows[0];
    if (!user) {
      return res.redirect('/login?error=expired_token');
    }

    await pool.query(
      `UPDATE users
       SET email_verified = TRUE,
           email_verification_token = NULL,
           email_verification_expires = NULL,
           updated_at = NOW()
       WHERE id = $1`,
      [user.id]
    );

    // Auto-login after verification
    const jwtToken = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Redirect to login with success flag + auto-login token
    res.redirect(`/login?verified=true&token=${jwtToken}`);
  } catch (err) {
    console.error('Email verification error:', err);
    res.redirect('/login?error=verification_failed');
  }
});

// ─── Rate limiter for forgot-password: 3 requests per email per hour
const _forgotRateLimits = new Map();
const _FORGOT_RATE_LIMIT = 3;
const _FORGOT_RATE_WINDOW = 60 * 60 * 1000; // 1 hour
setInterval(() => {
  const now = Date.now();
  for (const [email, entry] of _forgotRateLimits.entries()) {
    if (now - entry.window > _FORGOT_RATE_WINDOW * 2) _forgotRateLimits.delete(email);
  }
}, 5 * 60 * 1000);

function _forgotRateLimit(email) {
  const now = Date.now();
  const entry = _forgotRateLimits.get(email);
  if (!entry || now - entry.window > _FORGOT_RATE_WINDOW) {
    _forgotRateLimits.set(email, { count: 1, window: now });
    return { allowed: true, remaining: _FORGOT_RATE_LIMIT - 1 };
  }
  if (entry.count >= _FORGOT_RATE_LIMIT) {
    return { allowed: false, remaining: 0, retryAfter: Math.ceil((entry.window + _FORGOT_RATE_WINDOW - now) / 1000) };
  }
  entry.count++;
  return { allowed: true, remaining: _FORGOT_RATE_LIMIT - entry.count };
}

// ─── POST /api/auth/forgot-password ────────────────────
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Valid email address is required' });
    }
    const normalised = email.toLowerCase().trim();

    const rateCheck = _forgotRateLimit(normalised);
    if (!rateCheck.allowed) {
      return res.status(429).json({
        error: `Too many password reset requests. Please try again in ${Math.ceil(rateCheck.retryAfter / 60)} minutes.`,
      });
    }

    const result = await pool.query(
      'SELECT id, email, name FROM users WHERE LOWER(email) = $1',
      [normalised]
    );
    const user = result.rows[0];

    // Always return success to prevent email enumeration
    if (user) {
      const resetToken = crypto.randomBytes(32).toString('hex');
      const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      await pool.query(
        `UPDATE users
         SET password_reset_token = $1, password_reset_expires = $2, updated_at = NOW()
         WHERE id = $3`,
        [resetToken, expires, user.id]
      );

      const resetUrl = `${process.env.APP_URL || 'https://finowl.co.uk'}/reset-password?token=${resetToken}`;
      await sendAuthEmail({
        to: normalised,
        subject: 'Reset your FinOwl password',
        htmlBody: `
          <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:520px;margin:32px auto;background:#fff;border-radius:16px;overflow:hidden;border:1px solid #e5e2db;">
            <div style="background:#0a0f1a;padding:20px 28px;display:flex;align-items:center;gap:10px;">
              <span style="background:#d4920b;border-radius:50%;width:34px;height:34px;display:inline-flex;align-items:center;justify-content:center;font-size:16px;">🦉</span>
              <span style="color:#fff;font-size:18px;font-weight:700;letter-spacing:-0.3px;">FinOwl</span>
            </div>
            <div style="padding:28px;">
              <h2 style="font-size:1.3rem;margin-bottom:12px;color:#0a0f1a;">Reset your password</h2>
              <p style="color:#6b7280;margin-bottom:24px;line-height:1.6;">We received a request to reset the password for your FinOwl account. Click the button below to set a new password.</p>
              <a href="${resetUrl}" style="display:inline-block;background:#d4920b;color:#fff;padding:12px 28px;border-radius:10px;text-decoration:none;font-weight:600;font-size:1rem;">Reset password</a>
              <p style="margin-top:20px;color:#9ca3af;font-size:0.85rem;">This link expires in 1 hour. If you didn't request a password reset, you can ignore this email — your account is safe.</p>
              <hr style="border:none;border-top:1px solid #e5e2db;margin:20px 0;">
              <p style="color:#9ca3af;font-size:0.8rem;">Or copy this link:<br><span style="word-break:break-all;">${resetUrl}</span></p>
            </div>
          </div>
        `,
      }).catch(err => console.error('[Auth] Password reset email failed:', err.message));
    }

    res.json({ success: true, message: 'If an account exists with that email, a reset link has been sent.' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Failed to send reset email. Please try again.' });
  }
});

// ─── POST /api/auth/reset-password ─────────────────────
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, password, confirmPassword } = req.body;
    if (!token) return res.status(400).json({ error: 'Reset token is required' });

    const pwError = validatePassword(password);
    if (pwError) return res.status(400).json({ error: pwError });
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    const result = await pool.query(
      `SELECT id, email, name FROM users
       WHERE password_reset_token = $1
         AND password_reset_expires > NOW()`,
      [token]
    );
    const user = result.rows[0];
    if (!user) {
      return res.status(400).json({ error: 'This reset link has expired or is invalid. Please request a new one.' });
    }

    const hash = await bcrypt.hash(password, 12);

    await pool.query(
      `UPDATE users
       SET password_hash = $1,
           email_verified = TRUE,
           password_reset_token = NULL,
           password_reset_expires = NULL,
           updated_at = NOW()
       WHERE id = $2`,
      [hash, user.id]
    );

    // Auto-login after reset
    const jwtToken = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ success: true, token: jwtToken, user: { id: user.id, email: user.email, name: user.name } });
    try { logAuditEvent({ userId: user.id, eventType: 'user_password_reset', entityType: 'auth', entityId: user.id, details: { email: user.email }, req }); } catch (_) {}
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Failed to reset password. Please try again.' });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, name, created_at, subscribed_at, subscription_plan FROM users WHERE id = $1',
      [req.user.userId]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('Auth check error:', err);
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// ─── Activate subscription after Stripe checkout ────────
app.post('/api/auth/subscribe', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE users
       SET subscribed_at = COALESCE(subscribed_at, NOW()),
           updated_at = NOW()
       WHERE id = $1
       RETURNING id, email, name, subscribed_at`,
      [req.user.userId]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error('Subscribe error:', err);
    res.status(500).json({ error: 'Failed to activate subscription' });
  }
});

// ═══════════════════════════════════════════════════════════
// STRIPE CHECKOUT SESSION API  (Direct Stripe — user's own account)
// ═══════════════════════════════════════════════════════════

// ─── Stripe Checkout: create session ─────────────────────
app.post('/api/checkout/session', async (req, res) => {
  try {
    const { plan, token } = req.body;
    const validPlans = Object.keys(STRIPE_PLANS);
    if (!plan || !validPlans.includes(plan)) {
      return res.status(400).json({ error: 'Invalid plan. Valid plans: ' + validPlans.join(', ') });
    }

    // Resolve user email if token is provided
    let userEmail = null;
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const result = await pool.query('SELECT email FROM users WHERE id = $1', [decoded.userId]);
        if (result.rows[0]) userEmail = result.rows[0].email;
      } catch (_) {
        // Token invalid — allow anonymous checkout; Stripe collects email
      }
    }

    const url = await createCheckoutSession(plan, userEmail, token || '');
    res.json({ success: true, url });
  } catch (err) {
    console.error('[stripe-direct] Checkout session error:', err.message);
    if (err.message && err.message.includes('not configured')) {
      return res.status(503).json({ error: 'Stripe is not configured. Contact finowl@polsia.app.' });
    }
    res.status(500).json({ error: 'Failed to create checkout session. Please try again.' });
  }
});

// ─── Stripe Checkout: verify session ───────────────────────
// Called by /checkout/success to confirm payment before activating subscription
app.get('/api/checkout/verify', async (req, res) => {
  try {
    const { session_id } = req.query;
    if (!session_id) return res.status(400).json({ error: 'session_id required' });

    const details = await verifyCheckoutSession(session_id);
    res.json({
      success: true,
      subscription_id: details.subscription_id,
      customer_email: details.customer_email,
      amount_total: details.amount_total,
      currency: details.currency,
      plan: details.planKey,
      subscription_status: details.subscription_status,
    });
  } catch (err) {
    console.error('[stripe-direct] Verify error:', err.message);
    if (err.status) return res.status(402).json({ error: err.message, status: err.status });
    res.status(500).json({ error: 'Failed to verify checkout session.' });
  }
});

// ─── Ltd Company Interest Registration (public, no auth) ──
app.post('/api/ltd-interest', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Valid email address required' });
    }
    await pool.query(
      `INSERT INTO ltd_interest (email) VALUES ($1)
       ON CONFLICT (email) DO NOTHING`,
      [email.toLowerCase().trim()]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Ltd interest error:', err);
    res.status(500).json({ error: 'Failed to register interest' });
  }
});

// ═══════════════════════════════════════════════════════════
// CATEGORIES API
// ═══════════════════════════════════════════════════════════

app.get('/api/categories', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM categories ORDER BY sort_order');
    res.json({ categories: result.rows });
  } catch (err) {
    console.error('Categories error:', err);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

// ═══════════════════════════════════════════════════════════
// BANK CONNECTIONS API
// ═══════════════════════════════════════════════════════════

app.get('/api/bank/connections', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM bank_connections WHERE user_id = $1 ORDER BY connected_at DESC',
      [req.user.userId]
    );
    res.json({ connections: result.rows });
  } catch (err) {
    console.error('Bank connections error:', err);
    res.status(500).json({ error: 'Failed to fetch connections' });
  }
});

app.post('/api/bank/connect-demo', authenticateToken, requireOwner, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Check if user already has a demo bank
    const existing = await pool.query(
      'SELECT id FROM bank_connections WHERE user_id = $1 AND is_demo = true',
      [userId]
    );
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Demo bank already connected. Transactions were loaded when you connected.' });
    }

    // Create demo bank connection
    const bankResult = await pool.query(
      `INSERT INTO bank_connections (user_id, bank_name, account_name, account_type, sort_code, account_last4, is_demo, last_synced_at)
       VALUES ($1, 'Starling Bank', 'Business Current Account', 'business_current', '60-83', '4271', true, NOW())
       RETURNING *`,
      [userId]
    );
    const bank = bankResult.rows[0];

    // Generate realistic UK demo transactions for last 60 days (includes FX transactions)
    const transactions = generateDemoTransactions(userId, bank.id);
    const insertedIds = [];
    for (const tx of transactions) {
      await pool.query(
        `INSERT INTO transactions
           (user_id, bank_connection_id, date, description, amount, merchant_name, reference,
            original_currency, original_amount, exchange_rate, exchange_rate_date)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [tx.user_id, tx.bank_connection_id, tx.date, tx.description, tx.amount, tx.merchant_name, tx.reference,
         tx.original_currency || null, tx.original_amount || null, tx.exchange_rate || null, tx.exchange_rate_date || null]
      );
      if (ir.rows[0]) insertedIds.push(ir.rows[0].id);
    }
    // Non-blocking duplicate scan for new demo transactions
    setImmediate(async () => {
      for (const id of insertedIds) {
        await detectAndFlagDuplicates(userId, id);
      }
    });

    res.json({
      connection: bank,
      transactions_imported: transactions.length,
      message: `Connected demo bank and imported ${transactions.length} transactions`
    });
  } catch (err) {
    console.error('Connect demo error:', err);
    res.status(500).json({ error: 'Failed to connect demo bank' });
  }
});

// ═══════════════════════════════════════════════════════════
// TRUELAYER OPEN BANKING
// ═══════════════════════════════════════════════════════════

// ─── Config ─────────────────────────────────────────────────
const TRUELAYER_CLIENT_ID = process.env.TRUELAYER_CLIENT_ID || '';
const TRUELAYER_CLIENT_SECRET = process.env.TRUELAYER_CLIENT_SECRET || '';
const TRUELAYER_SANDBOX = (process.env.TRUELAYER_SANDBOX || 'true') !== 'false';
const TRUELAYER_AUTH_HOST = TRUELAYER_SANDBOX ? 'auth.truelayer-sandbox.com' : 'auth.truelayer.com';
const TRUELAYER_API_HOST = TRUELAYER_SANDBOX ? 'api.truelayer-sandbox.com' : 'api.truelayer.com';
const TRUELAYER_PROVIDERS = TRUELAYER_SANDBOX ? 'uk-cs-mock' : 'uk-ob-all uk-oauth-all';

// ─── Helpers ────────────────────────────────────────────────

// AES-256-GCM encryption for OAuth tokens
const ENC_KEY = (() => {
  const raw = process.env.ENCRYPTION_KEY || JWT_SECRET;
  // Ensure 32 bytes
  return crypto.createHash('sha256').update(raw).digest();
})();

function encryptToken(plaintext) {
  if (!plaintext) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

function decryptToken(ciphertext) {
  if (!ciphertext) return null;
  try {
    const buf = Buffer.from(ciphertext, 'base64');
    const iv = buf.slice(0, 12);
    const tag = buf.slice(12, 28);
    const encrypted = buf.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
    decipher.setAuthTag(tag);
    return decipher.update(encrypted) + decipher.final('utf8');
  } catch {
    return null;
  }
}

// Simple HTTPS request helper (no extra deps)
function tlRequest(host, path, method, headers, body) {
  return new Promise((resolve, reject) => {
    const opts = { hostname: host, path, method, headers: headers || {} };
    const req = https.request(opts, (res) => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// Exchange auth code for tokens
async function exchangeCode(code, redirectUri) {
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: TRUELAYER_CLIENT_ID,
    client_secret: TRUELAYER_CLIENT_SECRET,
    redirect_uri: redirectUri,
    code
  }).toString();

  const res = await tlRequest(TRUELAYER_AUTH_HOST, '/connect/token', 'POST', {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': Buffer.byteLength(params)
  }, params);

  if (res.status !== 200) throw new Error(`TrueLayer token exchange failed: ${JSON.stringify(res.body)}`);
  return res.body; // { access_token, refresh_token, expires_in, token_type }
}

// Refresh an access token
async function refreshAccessToken(refreshToken) {
  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: TRUELAYER_CLIENT_ID,
    client_secret: TRUELAYER_CLIENT_SECRET,
    refresh_token: refreshToken
  }).toString();

  const res = await tlRequest(TRUELAYER_AUTH_HOST, '/connect/token', 'POST', {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': Buffer.byteLength(params)
  }, params);

  if (res.status !== 200) throw new Error(`TrueLayer token refresh failed: ${JSON.stringify(res.body)}`);
  return res.body;
}

// Fetch all accounts for a user
async function tlGetAccounts(accessToken) {
  const res = await tlRequest(TRUELAYER_API_HOST, '/data/v1/accounts', 'GET', {
    'Authorization': `Bearer ${accessToken}`
  });
  if (res.status !== 200) throw new Error(`TrueLayer accounts failed: ${res.status}`);
  return res.body.results || [];
}

// Fetch account info
async function tlGetAccountInfo(accessToken, accountId) {
  const res = await tlRequest(TRUELAYER_API_HOST, `/data/v1/accounts/${accountId}`, 'GET', {
    'Authorization': `Bearer ${accessToken}`
  });
  if (res.status !== 200) throw new Error(`TrueLayer account info failed: ${res.status}`);
  return (res.body.results || [])[0] || null;
}

// Fetch transactions for an account
async function tlGetTransactions(accessToken, accountId, fromDate, toDate) {
  const qs = `?from=${fromDate}T00:00:00&to=${toDate}T23:59:59`;
  const res = await tlRequest(TRUELAYER_API_HOST, `/data/v1/accounts/${accountId}/transactions${qs}`, 'GET', {
    'Authorization': `Bearer ${accessToken}`
  });
  if (res.status !== 200) throw new Error(`TrueLayer transactions failed: ${res.status}`);
  return res.body.results || [];
}

// ─── Exchange Rate Service ────────────────────────────────────
// Uses open.er-api.com (free, no API key required)
// Rates are relative to GBP as the base currency
const _fxRateCache = {}; // key: "YYYY-MM-DD:USD" → GBP rate (1 unit of foreign = X GBP)

async function getExchangeRateToGBP(fromCurrency, date) {
  if (!fromCurrency || fromCurrency === 'GBP') return 1;
  const cacheKey = `${date}:${fromCurrency}`;
  if (_fxRateCache[cacheKey]) return _fxRateCache[cacheKey];

  try {
    const https = require('https');
    const url = `https://open.er-api.com/v6/latest/GBP`;
    const response = await new Promise((resolve, reject) => {
      https.get(url, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => { try { resolve(JSON.parse(data)); } catch (e) { reject(e); } });
      }).on('error', reject);
    });

    if (response.result === 'success' && response.rates) {
      // response.rates[fromCurrency] = units of fromCurrency per 1 GBP
      // To convert 1 unit of fromCurrency → GBP: divide by rate
      const ratePerGBP = response.rates[fromCurrency];
      if (ratePerGBP && ratePerGBP > 0) {
        const gbpRate = parseFloat((1 / ratePerGBP).toFixed(8));
        _fxRateCache[cacheKey] = gbpRate;
        // Also cache all rates from this response to minimise API calls
        for (const [ccy, r] of Object.entries(response.rates)) {
          if (r > 0) _fxRateCache[`${date}:${ccy}`] = parseFloat((1 / r).toFixed(8));
        }
        return gbpRate;
      }
    }
  } catch (err) {
    console.warn(`[FX] Rate fetch failed for ${fromCurrency}:`, err.message);
  }

  // Fallback hardcoded approximate rates if API fails
  const fallback = { USD: 0.79, EUR: 0.85, CAD: 0.58, AUD: 0.51, CHF: 0.89, JPY: 0.0053, SEK: 0.076, NOK: 0.073, DKK: 0.114 };
  return fallback[fromCurrency] || 1;
}

// Map TrueLayer transaction → FinOwl format (multi-currency aware)
async function mapTrueLayerTx(tlTx, userId, bankConnectionId) {
  const rawAmount = parseFloat(tlTx.amount) || 0;
  const date = tlTx.timestamp ? tlTx.timestamp.substring(0, 10) : new Date().toISOString().substring(0, 10);
  const description = tlTx.description || tlTx.transaction_id || '';
  const merchantName = tlTx.merchant_name || tlTx.meta?.provider_merchant_name || null;
  const reference = tlTx.transaction_id || null;
  const txCurrency = (tlTx.currency || 'GBP').toUpperCase();

  let amount = rawAmount;
  let originalCurrency = null;
  let originalAmount = null;
  let exchangeRate = null;
  let exchangeRateDate = null;

  if (txCurrency !== 'GBP') {
    const rate = await getExchangeRateToGBP(txCurrency, date);
    amount = parseFloat((rawAmount * rate).toFixed(2));
    originalCurrency = txCurrency;
    originalAmount = rawAmount;
    exchangeRate = rate;
    exchangeRateDate = date;
    console.log(`[FX] ${rawAmount} ${txCurrency} → £${amount} GBP (rate: ${rate})`);
  }

  return { userId, bankConnectionId, date, description, amount, merchantName, reference, originalCurrency, originalAmount, exchangeRate, exchangeRateDate };
}

// Get a valid access token for a connection (auto-refresh if needed)
async function getValidAccessToken(conn) {
  const now = new Date();
  const expiresAt = conn.token_expires_at ? new Date(conn.token_expires_at) : null;
  const needsRefresh = !expiresAt || expiresAt <= new Date(now.getTime() + 5 * 60 * 1000);

  let accessToken = decryptToken(conn.access_token_enc);

  if (needsRefresh && conn.refresh_token_enc) {
    const refreshToken = decryptToken(conn.refresh_token_enc);
    if (refreshToken) {
      try {
        const tokens = await refreshAccessToken(refreshToken);
        accessToken = tokens.access_token;
        const newExpiry = new Date(Date.now() + (tokens.expires_in || 3600) * 1000);
        await pool.query(
          `UPDATE bank_connections SET access_token_enc = $1, token_expires_at = $2, updated_at = NOW() WHERE id = $3`,
          [encryptToken(tokens.access_token), newExpiry, conn.id]
        );
      } catch (err) {
        console.error(`[TrueLayer] Token refresh failed for connection ${conn.id}:`, err.message);
      }
    }
  }

  return accessToken;
}

// Sync transactions for a bank connection
async function syncBankConnection(conn) {
  const accessToken = await getValidAccessToken(conn);
  if (!accessToken) throw new Error('No valid access token');

  await pool.query(`UPDATE bank_connections SET sync_status = 'syncing' WHERE id = $1`, [conn.id]);
  try { logAuditEvent({ userId: conn.user_id, eventType: 'bank_sync_triggered', entityType: 'bank_connection', entityId: conn.id, details: { bank_name: conn.bank_name, account_name: conn.account_name } }); } catch (_) {}

  try {
    // Fetch transactions for the last 90 days
    const toDate = new Date().toISOString().substring(0, 10);
    const fromDate = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString().substring(0, 10);

    const tlTxs = await tlGetTransactions(accessToken, conn.truelayer_account_id, fromDate, toDate);

    let imported = 0;
    for (const tlTx of tlTxs) {
      const tx = await mapTrueLayerTx(tlTx, conn.user_id, conn.id);
      // Upsert by external_id (transaction_id from TrueLayer)
      const extId = tlTx.transaction_id;
      if (extId) {
        const existing = await pool.query(
          `SELECT id FROM transactions WHERE bank_connection_id = $1 AND reference = $2`,
          [conn.id, extId]
        );
        if (existing.rows.length > 0) continue; // Already imported
      }

      const insertRes = await pool.query(
        `INSERT INTO transactions
           (user_id, bank_connection_id, date, description, amount, merchant_name, reference,
            original_currency, original_amount, exchange_rate, exchange_rate_date)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING id`,
        [tx.userId, tx.bankConnectionId, tx.date, tx.description, tx.amount, tx.merchantName, tx.reference,
         tx.originalCurrency, tx.originalAmount, tx.exchangeRate, tx.exchangeRateDate]
      );
      imported++;
      // Non-blocking duplicate detection
      if (insertRes.rows[0]) detectAndFlagDuplicates(tx.userId, insertRes.rows[0].id);
    }

    await pool.query(
      `UPDATE bank_connections SET sync_status = 'active', last_synced_at = NOW(), last_error = NULL WHERE id = $1`,
      [conn.id]
    );

    if (imported > 0) {
      try { logAuditEvent({ userId: conn.user_id, eventType: 'bank_transactions_imported', entityType: 'bank_connection', entityId: conn.id, details: { count: imported, total: tlTxs.length } }); } catch (_) {}
    }

    return { imported, total: tlTxs.length };
  } catch (err) {
    await pool.query(
      `UPDATE bank_connections SET sync_status = 'error', last_error = $1 WHERE id = $2`,
      [err.message, conn.id]
    );
    try { logAuditEvent({ userId: conn.user_id, eventType: 'bank_sync_error', entityType: 'bank_connection', entityId: conn.id, details: { error: err.message } }); } catch (_) {}
    throw err;
  }
}

// ─── OAuth: Initiate ─────────────────────────────────────────
// GET /api/auth/truelayer?token=<JWT>
// Redirects user to TrueLayer auth page
app.get('/api/auth/truelayer', authenticateTokenFromQuery, (req, res) => {
  if (!TRUELAYER_CLIENT_ID) {
    return res.redirect('/dashboard?bank_error=TrueLayer+not+configured');
  }

  const appUrl = process.env.APP_URL || `https://${req.headers.host}`;
  const redirectUri = `${appUrl}/api/auth/truelayer/callback`;

  // State encodes user identity and expiry (signed JWT)
  const state = jwt.sign(
    { userId: req.user.userId, nonce: crypto.randomBytes(8).toString('hex') },
    JWT_SECRET,
    { expiresIn: '10m' }
  );

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: TRUELAYER_CLIENT_ID,
    scope: 'info accounts balance transactions offline_access',
    redirect_uri: redirectUri,
    providers: TRUELAYER_PROVIDERS,
    state
  });

  const authUrl = `https://${TRUELAYER_AUTH_HOST}/?${params.toString()}`;
  console.log(`[TrueLayer] Auth redirect URL: ${authUrl}`);
  res.redirect(authUrl);
});

// ─── OAuth: Callback ─────────────────────────────────────────
// GET /api/auth/truelayer/callback?code=...&state=...
app.get('/api/auth/truelayer/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    console.error('[TrueLayer] OAuth error:', error);
    return res.redirect(`/dashboard?bank_error=${encodeURIComponent(error)}`);
  }

  if (!code || !state) {
    return res.redirect('/dashboard?bank_error=missing+params');
  }

  let userId;
  try {
    const decoded = jwt.verify(state, JWT_SECRET);
    userId = decoded.userId;
  } catch {
    return res.redirect('/dashboard?bank_error=invalid+state');
  }

  try {
    const appUrl = process.env.APP_URL || `https://${req.headers.host}`;
    const redirectUri = `${appUrl}/api/auth/truelayer/callback`;

    // Exchange code for tokens
    const tokens = await exchangeCode(code, redirectUri);
    const accessToken = tokens.access_token;
    const refreshToken = tokens.refresh_token;
    const expiresAt = new Date(Date.now() + (tokens.expires_in || 3600) * 1000);

    // Fetch accounts from TrueLayer
    const accounts = await tlGetAccounts(accessToken);

    if (!accounts.length) {
      return res.redirect('/dashboard?bank_error=no+accounts+found');
    }

    let totalImported = 0;
    let connectedCount = 0;

    for (const account of accounts) {
      const accountId = account.account_id;

      // Check if already connected
      const existing = await pool.query(
        `SELECT id FROM bank_connections WHERE user_id = $1 AND truelayer_account_id = $2`,
        [userId, accountId]
      );
      if (existing.rows.length > 0) continue;

      // Parse account details
      const bankName = account.provider?.display_name || account.provider?.provider_id || 'Open Banking';
      const accountName = account.display_name || account.account_type || 'Account';
      const accountType = (account.account_type || 'current').toLowerCase().replace(' ', '_');
      const accountNumber = account.account_number?.number || '';
      const sortCode = account.account_number?.sort_code || '';
      const last4 = accountNumber.slice(-4) || '****';
      const sortCodeFormatted = sortCode.length === 6
        ? `${sortCode.slice(0,2)}-${sortCode.slice(2,4)}-${sortCode.slice(4,6)}`
        : sortCode;

      // Create bank connection
      const connResult = await pool.query(
        `INSERT INTO bank_connections
           (user_id, bank_name, account_name, account_type, sort_code, account_last4,
            is_demo, provider, access_token_enc, refresh_token_enc, token_expires_at,
            truelayer_account_id, sync_status, last_synced_at)
         VALUES ($1, $2, $3, $4, $5, $6, false, 'truelayer', $7, $8, $9, $10, 'syncing', NOW())
         RETURNING *`,
        [
          userId, bankName, accountName, accountType, sortCodeFormatted, last4,
          encryptToken(accessToken), encryptToken(refreshToken), expiresAt, accountId
        ]
      );
      const conn = connResult.rows[0];
      connectedCount++;

      // Import transactions (last 90 days)
      try {
        const result = await syncBankConnection(conn);
        totalImported += result.imported;
      } catch (syncErr) {
        console.error(`[TrueLayer] Sync failed for account ${accountId}:`, syncErr.message);
      }
    }

    // Auto-categorise new transactions
    try {
      const uncatResult = await pool.query(
        `SELECT id, description, amount, merchant_name, date FROM transactions
         WHERE user_id = $1 AND category_id IS NULL AND is_manually_categorised = false
         ORDER BY date DESC LIMIT 50`,
        [userId]
      );
      if (uncatResult.rows.length > 0) {
        // Fire-and-forget categorisation (don't block the redirect)
        autoCategoiseTransactions(userId, uncatResult.rows).catch(e =>
          console.error('[TrueLayer] Auto-categorise error:', e.message)
        );
      }
    } catch { /* non-critical */ }

    const msg = connectedCount > 0
      ? `Connected ${connectedCount} account${connectedCount > 1 ? 's' : ''}, imported ${totalImported} transactions`
      : 'Accounts already connected';

    res.redirect(`/dashboard?bank_connected=true&msg=${encodeURIComponent(msg)}`);
  } catch (err) {
    console.error('[TrueLayer] Callback error:', err.message);
    res.redirect(`/dashboard?bank_error=${encodeURIComponent('Connection failed: ' + err.message)}`);
  }
});

// ─── Manual sync endpoint ─────────────────────────────────────
// POST /api/bank/sync/:connectionId
app.post('/api/bank/sync/:connectionId', authenticateToken, async (req, res) => {
  try {
    const { connectionId } = req.params;
    const connResult = await pool.query(
      `SELECT * FROM bank_connections WHERE id = $1 AND user_id = $2`,
      [connectionId, req.user.userId]
    );
    if (!connResult.rows[0]) {
      return res.status(404).json({ error: 'Bank connection not found' });
    }
    const conn = connResult.rows[0];

    if (conn.is_demo) {
      return res.status(400).json({ error: 'Demo accounts cannot be synced' });
    }
    if (!TRUELAYER_CLIENT_ID) {
      return res.status(400).json({ error: 'TrueLayer not configured' });
    }

    const result = await syncBankConnection(conn);
    res.json({ success: true, imported: result.imported, total: result.total });
  } catch (err) {
    console.error('Sync error:', err.message);
    res.status(500).json({ error: 'Sync failed: ' + err.message });
  }
});

// ─── Normalise merchant key for recurring pattern matching ───
function normaliseMerchantKey(tx) {
  const raw = (tx.merchant_name || tx.description || '').toLowerCase().trim();
  return raw
    .replace(/\s+\d{2}\/\d{2}\/\d{2,4}.*$/, '')   // strip trailing dates
    .replace(/\s+\*\s*\w+$/, '')                    // strip card ref suffix
    .replace(/\s+ref[\s:]\S+/i, '')                 // strip ref numbers
    .replace(/\s+\d{6,}$/, '')                      // strip trailing long numbers
    .replace(/\s+/g, ' ')
    .trim()
    .substring(0, 100);
}

// ─── Auto-categorise helper (reusable) ──────────────────────
async function autoCategoiseTransactions(userId, transactions) {
  // Step 0: Apply recurring pattern categories (highest confidence, skip AI)
  const recurringPatterns = await pool.query(
    `SELECT merchant_key, category_id, typical_amount FROM recurring_patterns
     WHERE user_id = $1 AND is_active = true AND category_id IS NOT NULL
       AND (user_marked_recurring IS NULL OR user_marked_recurring = true)`,
    [userId]
  );
  const patternMap = {};
  recurringPatterns.rows.forEach(p => { patternMap[p.merchant_key] = p; });

  const afterRecurring = [];
  for (const tx of transactions) {
    const key = normaliseMerchantKey(tx);
    const pattern = patternMap[key];
    if (pattern) {
      await pool.query(
        `UPDATE transactions
         SET category_id = $1, ai_confidence = 1.0, is_recurring = true, updated_at = NOW(),
             reconciled_status = CASE WHEN reconciled_status = 'unmatched' THEN 'matched' ELSE reconciled_status END,
             matched_at = CASE WHEN reconciled_status = 'unmatched' THEN NOW() ELSE matched_at END
         WHERE id = $2 AND user_id = $3 AND is_manually_categorised = false`,
        [pattern.category_id, tx.id, userId]
      );
    } else {
      afterRecurring.push(tx);
    }
  }

  const userRules = await pool.query(
    `SELECT merchant_pattern, category_id, vat_rate_override FROM categorisation_rules WHERE user_id = $1 AND is_active = true`, [userId]
  );
  const cats = await pool.query('SELECT id, name, slug FROM categories ORDER BY sort_order');
  const categoryMap = {};
  cats.rows.forEach(c => { categoryMap[c.slug] = c.id; });
  const categoryList = cats.rows.map(c => `${c.slug}: ${c.name}`).join('\n');

  const remainingForAI = [];
  for (const tx of afterRecurring) {
    const merchantKey = (tx.merchant_name || tx.description || '').toLowerCase();
    let matchedRule = null;
    for (const rule of userRules.rows) {
      const pattern = rule.merchant_pattern.toLowerCase();
      if (merchantKey === pattern || merchantKey.includes(pattern)) { matchedRule = rule; break; }
    }
    if (matchedRule) {
      await pool.query(
        `UPDATE transactions
         SET category_id = $1, ai_confidence = 1.0, categorisation_source = 'rule',
             vat_rate_override = $4, updated_at = NOW(),
             reconciled_status = CASE WHEN reconciled_status = 'unmatched' THEN 'matched' ELSE reconciled_status END,
             matched_at = CASE WHEN reconciled_status = 'unmatched' THEN NOW() ELSE matched_at END
         WHERE id = $2 AND user_id = $3 AND is_manually_categorised = false`,
        [matchedRule.category_id, tx.id, userId, matchedRule.vat_rate_override ?? null]
      );
    } else {
      remainingForAI.push(tx);
    }
  }

  if (!remainingForAI.length || !process.env.OPENAI_API_KEY) return;

  const txList = remainingForAI.map(t =>
    `ID:${t.id} | ${t.date} | ${t.description} | ${t.merchant_name || ''} | ${parseFloat(t.amount) >= 0 ? '+' : ''}${t.amount}`
  ).join('\n');

  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini', temperature: 0.1,
    messages: [
      { role: 'system', content: `Categorise UK business transactions. Available categories:\n${categoryList}\nRespond ONLY with JSON array: [{"id": <txId>, "slug": "<category-slug>", "confidence": 0.0-1.0}]` },
      { role: 'user', content: txList }
    ]
  });

  const jsonStr = completion.choices[0]?.message?.content?.match(/\[[\s\S]*\]/)?.[0];
  if (!jsonStr) return;
  const results = JSON.parse(jsonStr);
  for (const r of results) {
    const catId = categoryMap[r.slug];
    if (catId) {
      const conf = r.confidence || 0.8;
      await pool.query(
        `UPDATE transactions
         SET category_id = $1, ai_confidence = $2, categorisation_source = 'ai', updated_at = NOW(),
             reconciled_status = CASE
               WHEN reconciled_status = 'unmatched' AND $2::numeric >= 0.9 THEN 'matched'
               ELSE reconciled_status
             END,
             matched_at = CASE
               WHEN reconciled_status = 'unmatched' AND $2::numeric >= 0.9 THEN NOW()
               ELSE matched_at
             END
         WHERE id = $3 AND user_id = $4 AND is_manually_categorised = false`,
        [catId, conf, r.id, userId]
      );
    }
  }
}

// ─── Daily auto-sync ─────────────────────────────────────────
// Run once at startup after 30s delay, then every 24h
function scheduleDailySync() {
  const runSync = async () => {
    if (!TRUELAYER_CLIENT_ID) return;
    console.log('[TrueLayer] Running daily auto-sync...');
    try {
      const connections = await pool.query(
        `SELECT * FROM bank_connections WHERE provider = 'truelayer' AND status = 'active'`
      );
      for (const conn of connections.rows) {
        try {
          const result = await syncBankConnection(conn);
          console.log(`[TrueLayer] Synced connection ${conn.id}: ${result.imported} new transactions`);
          // Auto-categorise new uncategorised transactions
          const uncatResult = await pool.query(
            `SELECT id, description, amount, merchant_name, date FROM transactions
             WHERE user_id = $1 AND category_id IS NULL AND is_manually_categorised = false
             ORDER BY date DESC LIMIT 50`,
            [conn.user_id]
          );
          if (uncatResult.rows.length > 0) {
            await autoCategoiseTransactions(conn.user_id, uncatResult.rows);
          }
        } catch (err) {
          console.error(`[TrueLayer] Daily sync failed for connection ${conn.id}:`, err.message);
        }
      }
    } catch (err) {
      console.error('[TrueLayer] Daily sync error:', err.message);
    }
  };

  // First run after 30 seconds (let server start up)
  setTimeout(() => {
    runSync();
    setInterval(runSync, 24 * 60 * 60 * 1000);
  }, 30000);
}
scheduleDailySync();

// ═══════════════════════════════════════════════════════════
// TRANSACTIONS API
// ═══════════════════════════════════════════════════════════

app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { category, startDate, endDate, search, limit = 100, offset = 0 } = req.query;
    let query = `
      SELECT t.*, c.name as category_name, c.color as category_color, c.icon as category_icon, c.slug as category_slug,
             r.id as receipt_id, r.file_url as receipt_file_url, r.vendor as receipt_vendor, r.match_confidence as receipt_match_confidence
      FROM transactions t
      LEFT JOIN categories c ON t.category_id = c.id
      LEFT JOIN receipts r ON r.matched_transaction_id = t.id AND r.user_id = t.user_id
      WHERE t.user_id = $1
        AND (t.is_duplicate IS NULL OR t.is_duplicate = false)
    `;
    const params = [req.user.userId];
    let paramIdx = 2;

    if (category && category !== 'all') {
      query += ` AND c.slug = $${paramIdx}`;
      params.push(category);
      paramIdx++;
    }
    if (startDate) {
      query += ` AND t.date >= $${paramIdx}`;
      params.push(startDate);
      paramIdx++;
    }
    if (endDate) {
      query += ` AND t.date <= $${paramIdx}`;
      params.push(endDate);
      paramIdx++;
    }
    if (search) {
      query += ` AND (t.description ILIKE $${paramIdx} OR t.merchant_name ILIKE $${paramIdx})`;
      params.push(`%${search}%`);
      paramIdx++;
    }

    query += ` ORDER BY t.date DESC, t.id DESC LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
    params.push(parseInt(limit), parseInt(offset));

    const result = await pool.query(query, params);

    // Count total
    let countQuery = `SELECT COUNT(*) FROM transactions t LEFT JOIN categories c ON t.category_id = c.id WHERE t.user_id = $1 AND (t.is_duplicate IS NULL OR t.is_duplicate = false)`;
    const countParams = [req.user.userId];
    let cIdx = 2;
    if (category && category !== 'all') {
      countQuery += ` AND c.slug = $${cIdx}`;
      countParams.push(category);
      cIdx++;
    }
    if (search) {
      countQuery += ` AND (t.description ILIKE $${cIdx} OR t.merchant_name ILIKE $${cIdx})`;
      countParams.push(`%${search}%`);
    }
    const countResult = await pool.query(countQuery, countParams);

    res.json({
      transactions: result.rows,
      total: parseInt(countResult.rows[0].count),
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
  } catch (err) {
    console.error('Transactions error:', err);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

app.patch('/api/transactions/:id/category', authenticateToken, requireOwner, async (req, res) => {
  try {
    const { categoryId } = req.body;
    const userId = req.user.userId;

    // Capture old value for audit trail
    const oldRes = await pool.query(
      `SELECT t.*, c.name as category_name FROM transactions t
       LEFT JOIN categories c ON t.category_id = c.id
       WHERE t.id = $1 AND t.user_id = $2`,
      [req.params.id, userId]
    );

    const result = await pool.query(
      `UPDATE transactions
       SET category_id = $1, is_manually_categorised = true, categorisation_source = 'manual', updated_at = NOW(),
           reconciled_status = CASE WHEN reconciled_status = 'matched' THEN 'unmatched' ELSE reconciled_status END,
           matched_at = CASE WHEN reconciled_status = 'matched' THEN NULL ELSE matched_at END
       WHERE id = $2 AND user_id = $3 RETURNING *`,
      [categoryId, req.params.id, userId]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Transaction not found' });
    const tx = result.rows[0];

    // Fetch category name for alert context (non-blocking)
    pool.query('SELECT name FROM categories WHERE id = $1', [categoryId])
      .then(catRes => {
        if (catRes.rows[0]) tx.category_name = catRes.rows[0].name;
        sendUnusualTransactionAlert(pool, userId, tx).catch(() => {});
      })
      .catch(() => {});

    // Audit log (non-blocking)
    logAudit({
      userId,
      actionType: 'update',
      entityType: 'transaction',
      entityId: req.params.id,
      oldValue: oldRes.rows[0] || null,
      newValue: tx,
      req,
    });
    logAuditEvent({
      userId,
      eventType: 'transaction_categorised',
      entityType: 'transaction',
      entityId: req.params.id,
      details: {
        category_id: categoryId,
        old_category_id: oldRes.rows[0]?.category_id || null,
      },
      req,
    });

    res.json({ transaction: tx });
  } catch (err) {
    console.error('Update category error:', err);
    res.status(500).json({ error: 'Failed to update category' });
  }
});

// ═══════════════════════════════════════════════════════════
// AI CATEGORISATION
// ═══════════════════════════════════════════════════════════

app.post('/api/transactions/categorise', authenticateToken, requireOwner, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Get uncategorised transactions
    const uncategorised = await pool.query(
      `SELECT id, description, amount, merchant_name, date
       FROM transactions
       WHERE user_id = $1 AND category_id IS NULL AND is_manually_categorised = false
       ORDER BY date DESC
       LIMIT 50`,
      [userId]
    );

    if (uncategorised.rows.length === 0) {
      return res.json({ message: 'All transactions are already categorised', categorised: 0 });
    }

    // ── Step 1: Apply user rules first (rules take priority over AI) ──
    const userRules = await pool.query(
      `SELECT merchant_pattern, category_id, vat_rate_override FROM categorisation_rules WHERE user_id = $1 AND is_active = true`,
      [userId]
    );

    let ruleApplied = 0;
    const remainingForAI = [];

    for (const tx of uncategorised.rows) {
      const merchantKey = (tx.merchant_name || tx.description || '').toLowerCase();
      let matchedRule = null;

      for (const rule of userRules.rows) {
        const pattern = rule.merchant_pattern.toLowerCase();
        if (merchantKey === pattern || merchantKey.includes(pattern)) {
          matchedRule = rule;
          break;
        }
      }

      if (matchedRule) {
        await pool.query(
          `UPDATE transactions
           SET category_id = $1, ai_confidence = 1.0, categorisation_source = 'rule',
               vat_rate_override = $4, updated_at = NOW(),
               reconciled_status = CASE WHEN reconciled_status = 'unmatched' THEN 'matched' ELSE reconciled_status END,
               matched_at = CASE WHEN reconciled_status = 'unmatched' THEN NOW() ELSE matched_at END
           WHERE id = $2 AND user_id = $3 AND is_manually_categorised = false`,
          [matchedRule.category_id, tx.id, userId, matchedRule.vat_rate_override ?? null]
        );
        ruleApplied++;
      } else {
        remainingForAI.push(tx);
      }
    }

    if (remainingForAI.length === 0) {
      return res.json({ categorised: ruleApplied, total: uncategorised.rows.length, rule_applied: ruleApplied, ai_categorised: 0 });
    }

    // ── Step 2: AI categorise the rest ──
    const cats = await pool.query('SELECT id, name, slug FROM categories ORDER BY sort_order');
    const categoryMap = {};
    cats.rows.forEach(c => { categoryMap[c.slug] = c.id; });

    const categoryList = cats.rows.map(c => `${c.slug}: ${c.name}`).join('\n');

    const txList = remainingForAI.map(t =>
      `ID:${t.id} | ${t.date} | ${t.description} | ${t.merchant_name || ''} | ${parseFloat(t.amount) >= 0 ? '+' : ''}${t.amount}`
    ).join('\n');

    const completion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      temperature: 0.1,
      messages: [
        {
          role: 'system',
          content: `You are a UK bookkeeping AI. Categorise each bank transaction into exactly one category.

Available categories:
${categoryList}

Rules:
- Positive amounts are usually "income" (client payments, refunds received)
- "income" is for money received from clients/customers
- Use "uncategorised" only if genuinely unclear
- Return ONLY valid JSON array, no other text

Return format: [{"id": <transaction_id>, "slug": "<category_slug>", "confidence": <0.0-1.0>}]`
        },
        {
          role: 'user',
          content: `Categorise these UK business transactions:\n${txList}`
        }
      ],
      task: 'categorise-transactions'
    });

    let categorisations = [];
    try {
      const content = completion.choices[0].message.content.trim();
      const jsonMatch = content.match(/\[[\s\S]*\]/);
      if (jsonMatch) {
        categorisations = JSON.parse(jsonMatch[0]);
      }
    } catch (parseErr) {
      console.error('AI parse error:', parseErr);
      return res.status(500).json({ error: 'AI returned invalid response' });
    }

    let aiUpdated = 0;
    for (const cat of categorisations) {
      const catId = categoryMap[cat.slug];
      if (catId && cat.id) {
        const catConf = cat.confidence || 0.8;
        await pool.query(
          `UPDATE transactions
           SET category_id = $1, ai_confidence = $2, categorisation_source = 'ai', updated_at = NOW(),
               reconciled_status = CASE
                 WHEN reconciled_status = 'unmatched' AND $2::numeric >= 0.9 THEN 'matched'
                 ELSE reconciled_status
               END,
               matched_at = CASE
                 WHEN reconciled_status = 'unmatched' AND $2::numeric >= 0.9 THEN NOW()
                 ELSE matched_at
               END
           WHERE id = $3 AND user_id = $4 AND is_manually_categorised = false`,
          [catId, catConf, cat.id, userId]
        );
        aiUpdated++;
      }
    }

    res.json({
      categorised: ruleApplied + aiUpdated,
      total: uncategorised.rows.length,
      rule_applied: ruleApplied,
      ai_categorised: aiUpdated
    });
  } catch (err) {
    console.error('Categorise error:', err);
    res.status(500).json({ error: 'AI categorisation failed' });
  }
});

// ═══════════════════════════════════════════════════════════
// DASHBOARD API
// ═══════════════════════════════════════════════════════════

app.get('/api/dashboard/summary', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Overall totals
    const totals = await pool.query(`
      SELECT
        COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as total_income,
        COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as total_expenses,
        COALESCE(SUM(amount), 0) as net,
        COUNT(*) as total_transactions,
        COUNT(CASE WHEN category_id IS NULL THEN 1 END) as uncategorised_count
      FROM transactions WHERE user_id = $1
    `, [userId]);

    // Category breakdown
    const categories = await pool.query(`
      SELECT c.name, c.slug, c.color, c.icon,
        COUNT(t.id) as count,
        COALESCE(SUM(ABS(t.amount)), 0) as total
      FROM transactions t
      JOIN categories c ON t.category_id = c.id
      WHERE t.user_id = $1
      GROUP BY c.id, c.name, c.slug, c.color, c.icon
      ORDER BY total DESC
    `, [userId]);

    // Monthly totals (last 6 months)
    const monthly = await pool.query(`
      SELECT
        TO_CHAR(date, 'YYYY-MM') as month,
        COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as income,
        COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as expenses
      FROM transactions
      WHERE user_id = $1 AND date >= NOW() - INTERVAL '6 months'
      GROUP BY TO_CHAR(date, 'YYYY-MM')
      ORDER BY month
    `, [userId]);

    // Recent transactions
    const recent = await pool.query(`
      SELECT t.*, c.name as category_name, c.color as category_color, c.icon as category_icon
      FROM transactions t
      LEFT JOIN categories c ON t.category_id = c.id
      WHERE t.user_id = $1
      ORDER BY t.date DESC, t.id DESC
      LIMIT 10
    `, [userId]);

    // Bank connections
    const banks = await pool.query(
      'SELECT * FROM bank_connections WHERE user_id = $1',
      [userId]
    );

    // Duplicate count (graceful — table may not exist yet on older DBs)
    let duplicateCount = 0;
    try {
      const dupeRes = await pool.query(
        `SELECT COUNT(*) FROM duplicate_pairs WHERE user_id = $1 AND status = 'pending'`,
        [userId]
      );
      duplicateCount = parseInt(dupeRes.rows[0].count);
    } catch (_) { /* table not yet migrated */ }

    res.json({
      totals: totals.rows[0],
      categories: categories.rows,
      monthly: monthly.rows,
      recent_transactions: recent.rows,
      bank_connections: banks.rows,
      duplicate_count: duplicateCount
    });
  } catch (err) {
    console.error('Dashboard summary error:', err);
    res.status(500).json({ error: 'Failed to get dashboard summary' });
  }
});

// ═══════════════════════════════════════════════════════════
// FINANCIAL SUMMARY API — income vs expenses by month + MTD + VAT
// GET /api/dashboard/financial-summary?months=6
// ═══════════════════════════════════════════════════════════

app.get('/api/dashboard/financial-summary', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const months = Math.min(24, Math.max(1, parseInt(req.query.months) || 6));

    // MTD (month-to-date) totals
    const mtdResult = await pool.query(`
      SELECT
        COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) AS income,
        COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) AS expenses
      FROM transactions
      WHERE user_id = $1
        AND date >= date_trunc('month', NOW())
        AND date < date_trunc('month', NOW()) + INTERVAL '1 month'
    `, [userId]);

    const mtd = mtdResult.rows[0];
    mtd.net = parseFloat(mtd.income) - parseFloat(mtd.expenses);

    // Monthly breakdown for last N months
    const monthlyResult = await pool.query(`
      SELECT
        TO_CHAR(date_trunc('month', date), 'YYYY-MM') AS month,
        TO_CHAR(date_trunc('month', date), 'Mon YY') AS label,
        COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) AS income,
        COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) AS expenses
      FROM transactions
      WHERE user_id = $1
        AND date >= date_trunc('month', NOW()) - (($2 - 1) || ' months')::interval
      GROUP BY date_trunc('month', date)
      ORDER BY month ASC
    `, [userId, months]);

    // VAT owed — current quarter net liability (output VAT - input VAT)
    const now = new Date();
    const q = Math.ceil((now.getMonth() + 1) / 3);
    const year = now.getFullYear();
    const quarterMonths = { 1: ['01-01', '03-31'], 2: ['04-01', '06-30'], 3: ['07-01', '09-30'], 4: ['10-01', '12-31'] };
    const [qStart, qEnd] = quarterMonths[q];
    const quarterLabel = `Q${q}-${year}`;

    const vatResult = await pool.query(`
      SELECT t.amount, c.is_income, COALESCE(t.vat_rate_override, c.vat_rate) AS vat_rate
      FROM transactions t
      JOIN categories c ON t.category_id = c.id
      WHERE t.user_id = $1
        AND t.date >= $2 AND t.date <= $3
        AND COALESCE(t.vat_rate_override, c.vat_rate) IS NOT NULL
    `, [userId, `${year}-${qStart}`, `${year}-${qEnd}`]);

    let outputVat = 0, inputVat = 0;
    for (const row of vatResult.rows) {
      const gross = Math.abs(parseFloat(row.amount));
      const rate = parseFloat(row.vat_rate);
      const vatAmount = gross - (gross / (1 + rate / 100));
      if (row.is_income) {
        outputVat += vatAmount;
      } else {
        inputVat += vatAmount;
      }
    }
    const netLiability = parseFloat((outputVat - inputVat).toFixed(2));

    res.json({
      mtd: {
        income: parseFloat(parseFloat(mtd.income).toFixed(2)),
        expenses: parseFloat(parseFloat(mtd.expenses).toFixed(2)),
        net: parseFloat(mtd.net.toFixed(2)),
      },
      monthly: monthlyResult.rows.map(r => ({
        month: r.month,
        label: r.label,
        income: parseFloat(parseFloat(r.income).toFixed(2)),
        expenses: parseFloat(parseFloat(r.expenses).toFixed(2)),
      })),
      vat: {
        quarter: quarterLabel,
        output_vat: parseFloat(outputVat.toFixed(2)),
        input_vat: parseFloat(inputVat.toFixed(2)),
        net_liability: netLiability,
        payable: netLiability > 0,
      },
    });
  } catch (err) {
    console.error('Financial summary error:', err);
    res.status(500).json({ error: 'Failed to get financial summary' });
  }
});

// ═══════════════════════════════════════════════════════════
// AI INSIGHTS
// ═══════════════════════════════════════════════════════════

// Helper: build transaction context for AI analysis
async function buildInsightContext(userId) {
  // Current period: last 30 days
  const current = await pool.query(`
    SELECT
      COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as total_income,
      COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as total_expenses,
      COALESCE(SUM(amount), 0) as net,
      COUNT(*) as transaction_count
    FROM transactions
    WHERE user_id = $1 AND date >= NOW() - INTERVAL '30 days'
  `, [userId]);

  // Prior period: 30-60 days ago (for comparison)
  const prior = await pool.query(`
    SELECT
      COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as total_income,
      COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as total_expenses,
      COALESCE(SUM(amount), 0) as net
    FROM transactions
    WHERE user_id = $1 AND date >= NOW() - INTERVAL '60 days' AND date < NOW() - INTERVAL '30 days'
  `, [userId]);

  // Category breakdown (current period)
  const categories = await pool.query(`
    SELECT c.name, c.slug, c.is_income,
      COUNT(t.id) as count,
      ROUND(COALESCE(SUM(ABS(t.amount)), 0)::numeric, 2) as total
    FROM transactions t
    JOIN categories c ON t.category_id = c.id
    WHERE t.user_id = $1 AND t.date >= NOW() - INTERVAL '30 days'
    GROUP BY c.id, c.name, c.slug, c.is_income
    ORDER BY total DESC
    LIMIT 10
  `, [userId]);

  // Prior period category breakdown
  const priorCategories = await pool.query(`
    SELECT c.name, c.slug,
      ROUND(COALESCE(SUM(ABS(t.amount)), 0)::numeric, 2) as total
    FROM transactions t
    JOIN categories c ON t.category_id = c.id
    WHERE t.user_id = $1 AND t.date >= NOW() - INTERVAL '60 days' AND t.date < NOW() - INTERVAL '30 days'
    GROUP BY c.id, c.name, c.slug
  `, [userId]);

  // Top merchants (current period, expenses only)
  const merchants = await pool.query(`
    SELECT merchant_name, description,
      COUNT(*) as count,
      ROUND(SUM(ABS(amount))::numeric, 2) as total
    FROM transactions
    WHERE user_id = $1
      AND amount < 0
      AND date >= NOW() - INTERVAL '30 days'
      AND (merchant_name IS NOT NULL AND merchant_name != '')
    GROUP BY merchant_name, description
    ORDER BY total DESC
    LIMIT 8
  `, [userId]);

  // Monthly income trend (last 3 months)
  const monthly = await pool.query(`
    SELECT
      TO_CHAR(date, 'Mon YYYY') as month,
      TO_CHAR(date, 'YYYY-MM') as month_key,
      ROUND(COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0)::numeric, 2) as income,
      ROUND(COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0)::numeric, 2) as expenses
    FROM transactions
    WHERE user_id = $1 AND date >= NOW() - INTERVAL '3 months'
    GROUP BY TO_CHAR(date, 'Mon YYYY'), TO_CHAR(date, 'YYYY-MM')
    ORDER BY month_key
  `, [userId]);

  // Subscriptions/recurring (potential unused — purchased 2+ months ago but this month)
  const possiblyUnused = await pool.query(`
    SELECT merchant_name,
      ROUND(SUM(ABS(amount))::numeric, 2) as monthly_spend,
      COUNT(*) as occurrences
    FROM transactions
    WHERE user_id = $1
      AND amount < 0
      AND date >= NOW() - INTERVAL '90 days'
      AND (merchant_name IS NOT NULL AND merchant_name != '')
    GROUP BY merchant_name
    HAVING COUNT(*) >= 2 AND MAX(date) >= NOW() - INTERVAL '45 days'
    ORDER BY monthly_spend DESC
    LIMIT 6
  `, [userId]);

  const priorCatMap = {};
  priorCategories.rows.forEach(r => { priorCatMap[r.slug] = parseFloat(r.total); });

  return {
    period: 'last 30 days',
    current: {
      total_income: parseFloat(current.rows[0].total_income),
      total_expenses: parseFloat(current.rows[0].total_expenses),
      net: parseFloat(current.rows[0].net),
      transaction_count: parseInt(current.rows[0].transaction_count)
    },
    prior: {
      total_income: parseFloat(prior.rows[0].total_income),
      total_expenses: parseFloat(prior.rows[0].total_expenses),
      net: parseFloat(prior.rows[0].net)
    },
    categories: categories.rows.map(r => ({
      name: r.name,
      slug: r.slug,
      is_income: r.is_income,
      count: parseInt(r.count),
      total: parseFloat(r.total),
      prior_total: priorCatMap[r.slug] || 0,
      change_pct: priorCatMap[r.slug]
        ? Math.round(((parseFloat(r.total) - priorCatMap[r.slug]) / priorCatMap[r.slug]) * 100)
        : null
    })),
    top_merchants: merchants.rows.map(r => ({
      name: r.merchant_name,
      count: parseInt(r.count),
      total: parseFloat(r.total)
    })),
    monthly_trend: monthly.rows,
    recurring_merchants: possiblyUnused.rows.map(r => ({
      name: r.merchant_name,
      monthly_spend: parseFloat(r.monthly_spend),
      occurrences: parseInt(r.occurrences)
    }))
  };
}

// Helper: generate insights via AI
async function generateInsights(userId) {
  const context = await buildInsightContext(userId);

  // Only generate if there's enough data
  if (context.current.transaction_count < 3) {
    return [{
      type: 'tip',
      title: 'Connect your bank to unlock insights',
      body: 'Once you have a few weeks of transactions, I\'ll analyse your spending patterns and highlight what\'s working — and what isn\'t.',
      icon: '🔗',
      sort_order: 0
    }];
  }

  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    temperature: 0.4,
    messages: [
      {
        role: 'system',
        content: `You are a friendly, plain-English financial advisor for UK small business owners and sole traders.
Analyse the provided financial data and return exactly 4-5 concise insights in JSON format.

Insight types:
- "summary": Overall financial health snapshot
- "anomaly": Something unusual — a spending spike, unexpected drop, or one-off charge
- "trend": A notable pattern over time (growing income, rising category costs, etc.)
- "tip": Actionable advice the user can act on now

Rules:
- Use plain English, like a smart friend explaining their money. No jargon.
- Be specific: use actual numbers and names from the data (e.g. "£340 on software" not "some software costs")
- Keep each body under 2 sentences
- For change_pct, flag anything ≥25% as notable
- Do not repeat the same insight twice
- Return ONLY a valid JSON array, nothing else

Return format:
[{"type":"summary|anomaly|trend|tip","title":"Short headline","body":"Plain-English explanation with specific figures.","icon":"single emoji"}]`
      },
      {
        role: 'user',
        content: `Here is the financial data for this user:\n${JSON.stringify(context, null, 2)}`
      }
    ],
    task: 'generate-insights'
  });

  let insights = [];
  try {
    const content = completion.choices[0].message.content.trim();
    const jsonMatch = content.match(/\[[\s\S]*\]/);
    if (jsonMatch) {
      insights = JSON.parse(jsonMatch[0]);
    }
  } catch (parseErr) {
    console.error('[Insights] AI parse error:', parseErr);
    throw new Error('AI returned invalid response');
  }

  return insights.slice(0, 5).map((ins, i) => ({
    type: ins.type || 'tip',
    title: ins.title || 'Financial insight',
    body: ins.body || '',
    icon: ins.icon || '💡',
    sort_order: i
  }));
}

// Helper: save insights to DB (replaces existing)
async function saveInsights(userId, insights) {
  // Delete old insights for this user
  await pool.query('DELETE FROM insights WHERE user_id = $1', [userId]);

  // Insert new insights
  for (const ins of insights) {
    await pool.query(
      `INSERT INTO insights (user_id, insight_type, title, body, icon, sort_order, generated_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
      [userId, ins.type, ins.title, ins.body, ins.icon, ins.sort_order]
    );
  }
}

// GET /api/insights — return cached insights (or generate if stale/missing)
app.get('/api/insights', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Check for fresh insights (generated in last 7 days)
    const cached = await pool.query(
      `SELECT * FROM insights WHERE user_id = $1
       AND generated_at > NOW() - INTERVAL '7 days'
       ORDER BY sort_order ASC`,
      [userId]
    );

    if (cached.rows.length > 0) {
      return res.json({
        insights: cached.rows,
        generated_at: cached.rows[0].generated_at,
        cached: true
      });
    }

    // Generate fresh insights
    const insights = await generateInsights(userId);
    await saveInsights(userId, insights);

    const fresh = await pool.query(
      `SELECT * FROM insights WHERE user_id = $1 ORDER BY sort_order ASC`,
      [userId]
    );

    res.json({
      insights: fresh.rows,
      generated_at: fresh.rows[0]?.generated_at || new Date(),
      cached: false
    });
  } catch (err) {
    console.error('[Insights] GET error:', err);
    res.status(500).json({ error: 'Failed to load insights' });
  }
});

// POST /api/insights/refresh — force-regenerate insights
app.post('/api/insights/refresh', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const insights = await generateInsights(userId);
    await saveInsights(userId, insights);

    const fresh = await pool.query(
      `SELECT * FROM insights WHERE user_id = $1 ORDER BY sort_order ASC`,
      [userId]
    );

    res.json({
      insights: fresh.rows,
      generated_at: fresh.rows[0]?.generated_at || new Date(),
      cached: false
    });
  } catch (err) {
    console.error('[Insights] Refresh error:', err);
    res.status(500).json({ error: 'Failed to refresh insights' });
  }
});

// ═══════════════════════════════════════════════════════════
// DEMO DATA GENERATOR
// ═══════════════════════════════════════════════════════════

function generateDemoTransactions(userId, bankId) {
  const now = new Date();
  const transactions = [];

  // Income transactions (positive) — includes international FX transactions
  const incomeTemplates = [
    { desc: 'CLIENT PAYMENT - ACME LTD', merchant: 'Acme Ltd', min: 800, max: 5000 },
    { desc: 'BACS PAYMENT - BRIGHT SOLUTIONS', merchant: 'Bright Solutions', min: 1200, max: 4500 },
    { desc: 'FPS CREDIT - JOHNSON & CO', merchant: 'Johnson & Co', min: 500, max: 3000 },
    { desc: 'CLIENT PAYMENT - OAKWOOD DESIGN', merchant: 'Oakwood Design', min: 600, max: 2500 },
    { desc: 'INVOICE 1047 - HARRISON GROUP', merchant: 'Harrison Group', min: 1500, max: 6000 },
    { desc: 'STRIPE PAYOUT', merchant: 'Stripe', min: 200, max: 1800 },
    { desc: 'PAYPAL TRANSFER', merchant: 'PayPal', min: 50, max: 800 },
    // International clients paying in USD
    { desc: 'WIRE TRANSFER - TECHCORP INC', merchant: 'TechCorp Inc', min: 1500, max: 9000, currency: 'USD', rate: 0.79 },
    { desc: 'WIRE TRANSFER - NOVA SYSTEMS LLC', merchant: 'Nova Systems LLC', min: 800, max: 4500, currency: 'USD', rate: 0.79 },
    { desc: 'ACH CREDIT - BLUESTONE VENTURES', merchant: 'Bluestone Ventures', min: 600, max: 3000, currency: 'USD', rate: 0.79 },
    // European clients paying in EUR
    { desc: 'SEPA CREDIT - WEBFLUX GMBH', merchant: 'Webflux GmbH', min: 1000, max: 6000, currency: 'EUR', rate: 0.85 },
    { desc: 'SEPA CREDIT - DESIGNHAUS BERLIN', merchant: 'Designhaus Berlin', min: 700, max: 3500, currency: 'EUR', rate: 0.85 },
  ];

  // Expense transactions (negative)
  const expenseTemplates = [
    { desc: 'DIRECT DEBIT - BRITISH GAS', merchant: 'British Gas', min: 80, max: 200, recurring: true },
    { desc: 'DIRECT DEBIT - BT BROADBAND', merchant: 'BT', min: 35, max: 55, recurring: true },
    { desc: 'CARD PAYMENT - AMAZON UK', merchant: 'Amazon', min: 15, max: 200 },
    { desc: 'CARD PAYMENT - TESCO', merchant: 'Tesco', min: 5, max: 80 },
    { desc: 'CARD PAYMENT - SAINSBURYS', merchant: "Sainsbury's", min: 8, max: 60 },
    { desc: 'DIRECT DEBIT - HMRC VAT', merchant: 'HMRC', min: 500, max: 3000 },
    { desc: 'DIRECT DEBIT - HMRC PAYE', merchant: 'HMRC', min: 300, max: 1500 },
    { desc: 'CARD PAYMENT - PRET A MANGER', merchant: 'Pret A Manger', min: 4, max: 15 },
    { desc: 'CARD PAYMENT - COSTA COFFEE', merchant: 'Costa Coffee', min: 3, max: 8 },
    { desc: 'SUBSCRIPTION - SLACK', merchant: 'Slack', min: 6, max: 25, recurring: true },
    { desc: 'SUBSCRIPTION - GOOGLE WORKSPACE', merchant: 'Google', min: 10, max: 30, recurring: true },
    { desc: 'SUBSCRIPTION - XERO', merchant: 'Xero', min: 25, max: 40, recurring: true },
    { desc: 'DIRECT DEBIT - AVIVA INSURANCE', merchant: 'Aviva', min: 60, max: 150, recurring: true },
    { desc: 'CARD PAYMENT - RYMAN', merchant: 'Ryman', min: 10, max: 50 },
    { desc: 'CARD PAYMENT - TRAINLINE', merchant: 'Trainline', min: 20, max: 120 },
    { desc: 'CARD PAYMENT - TFL', merchant: 'TfL', min: 5, max: 15 },
    { desc: 'DIRECT DEBIT - VODAFONE', merchant: 'Vodafone', min: 25, max: 45, recurring: true },
    { desc: 'CARD PAYMENT - WH SMITH', merchant: 'WH Smith', min: 3, max: 20 },
    { desc: 'BANK CHARGES - MONTHLY FEE', merchant: 'Starling Bank', min: 0, max: 5 },
    { desc: 'CARD PAYMENT - UBER', merchant: 'Uber', min: 8, max: 35 },
    { desc: 'CARD PAYMENT - DELIVEROO', merchant: 'Deliveroo', min: 12, max: 40 },
    { desc: 'DIRECT DEBIT - WORKSPACE RENT', merchant: 'WeWork', min: 400, max: 600, recurring: true },
    { desc: 'CARD PAYMENT - STAPLES', merchant: 'Staples', min: 15, max: 80 },
    { desc: 'FPS PAYMENT - FREELANCER', merchant: 'Freelancer Payment', min: 200, max: 800 },
  ];

  // Generate 60 days of transactions
  for (let day = 0; day < 60; day++) {
    const date = new Date(now);
    date.setDate(date.getDate() - day);
    const dateStr = date.toISOString().split('T')[0];

    // Skip some weekends for realism
    if (date.getDay() === 0 && Math.random() > 0.2) continue;

    // 0-3 expenses per day
    const numExpenses = Math.floor(Math.random() * 4);
    for (let i = 0; i < numExpenses; i++) {
      const tmpl = expenseTemplates[Math.floor(Math.random() * expenseTemplates.length)];
      const amount = -(tmpl.min + Math.random() * (tmpl.max - tmpl.min)).toFixed(2);
      transactions.push({
        user_id: userId,
        bank_connection_id: bankId,
        date: dateStr,
        description: tmpl.desc,
        amount: parseFloat(amount),
        merchant_name: tmpl.merchant,
        reference: `REF${Math.random().toString(36).substring(2, 8).toUpperCase()}`
      });
    }

    // Income every few days
    if (day % 5 === 0 || (day % 3 === 0 && Math.random() > 0.5)) {
      const tmpl = incomeTemplates[Math.floor(Math.random() * incomeTemplates.length)];
      const isFX = !!(tmpl.currency && tmpl.currency !== 'GBP');
      const rawAmount = parseFloat((tmpl.min + Math.random() * (tmpl.max - tmpl.min)).toFixed(2));
      const gbpAmount = isFX ? parseFloat((rawAmount * tmpl.rate).toFixed(2)) : rawAmount;
      transactions.push({
        user_id: userId,
        bank_connection_id: bankId,
        date: dateStr,
        description: tmpl.desc,
        amount: gbpAmount,
        merchant_name: tmpl.merchant,
        reference: `INV${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
        original_currency: isFX ? tmpl.currency : null,
        original_amount: isFX ? rawAmount : null,
        exchange_rate: isFX ? tmpl.rate : null,
        exchange_rate_date: isFX ? dateStr : null,
      });
    }
  }

  return transactions;
}

// ═══════════════════════════════════════════════════════════
// VAT SETTINGS API
// ═══════════════════════════════════════════════════════════

app.get('/api/vat/settings', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM vat_settings WHERE user_id = $1',
      [req.user.userId]
    );
    // Return defaults if no settings saved yet
    const settings = result.rows[0] || {
      vat_number: null,
      scheme_type: 'standard',
      period_start_month: 4
    };
    res.json({ settings });
  } catch (err) {
    console.error('VAT settings error:', err);
    res.status(500).json({ error: 'Failed to fetch VAT settings' });
  }
});

app.post('/api/vat/settings', authenticateToken, requireOwner, async (req, res) => {
  try {
    const { vat_number, scheme_type, period_start_month } = req.body;
    const userId = req.user.userId;

    const oldRes = await pool.query('SELECT * FROM vat_settings WHERE user_id = $1', [userId]);

    const result = await pool.query(
      `INSERT INTO vat_settings (user_id, vat_number, scheme_type, period_start_month)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id) DO UPDATE
         SET vat_number = EXCLUDED.vat_number,
             scheme_type = EXCLUDED.scheme_type,
             period_start_month = EXCLUDED.period_start_month,
             updated_at = NOW()
       RETURNING *`,
      [userId, vat_number || null, scheme_type || 'standard', period_start_month || 4]
    );

    const isCreate = oldRes.rows.length === 0;
    logAudit({
      userId,
      actionType: isCreate ? 'create' : 'update',
      entityType: 'vat_setting',
      entityId: userId,
      oldValue: isCreate ? null : oldRes.rows[0],
      newValue: result.rows[0],
      req,
    });

    res.json({ settings: result.rows[0] });
  } catch (err) {
    console.error('VAT settings save error:', err);
    res.status(500).json({ error: 'Failed to save VAT settings' });
  }
});

// ═══════════════════════════════════════════════════════════
// VAT SUMMARY API
// Returns HMRC MTD Box 1-9 values for a given quarter
// Usage: GET /api/vat/summary?quarter=Q1-2026
// ═══════════════════════════════════════════════════════════

app.get('/api/vat/summary', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { quarter } = req.query;

    // Parse quarter param (e.g. "Q2-2026" → Apr 1 – Jun 30 2026)
    let startDate, endDate, quarterLabel;
    if (quarter) {
      const match = quarter.match(/^Q([1-4])-(\d{4})$/);
      if (!match) {
        return res.status(400).json({ error: 'Invalid quarter format. Use Q1-2026, Q2-2026, etc.' });
      }
      const q = parseInt(match[1]);
      const year = parseInt(match[2]);
      const quarterMonths = {
        1: { start: `${year}-01-01`, end: `${year}-03-31` },
        2: { start: `${year}-04-01`, end: `${year}-06-30` },
        3: { start: `${year}-07-01`, end: `${year}-09-30` },
        4: { start: `${year}-10-01`, end: `${year}-12-31` },
      };
      startDate = quarterMonths[q].start;
      endDate = quarterMonths[q].end;
      quarterLabel = quarter;
    } else {
      // Default: current calendar quarter
      const now = new Date();
      const year = now.getFullYear();
      const month = now.getMonth() + 1; // 1-12
      const q = Math.ceil(month / 3);
      const quarterMonths = {
        1: { start: `${year}-01-01`, end: `${year}-03-31` },
        2: { start: `${year}-04-01`, end: `${year}-06-30` },
        3: { start: `${year}-07-01`, end: `${year}-09-30` },
        4: { start: `${year}-10-01`, end: `${year}-12-31` },
      };
      startDate = quarterMonths[q].start;
      endDate = quarterMonths[q].end;
      quarterLabel = `Q${q}-${year}`;
    }

    // Fetch all transactions in the quarter that have a category with a VAT rate
    const result = await pool.query(`
      SELECT
        t.amount,
        c.is_income,
        COALESCE(t.vat_rate_override, c.vat_rate) AS vat_rate
      FROM transactions t
      JOIN categories c ON t.category_id = c.id
      WHERE t.user_id = $1
        AND t.date >= $2
        AND t.date <= $3
        AND COALESCE(t.vat_rate_override, c.vat_rate) IS NOT NULL
    `, [userId, startDate, endDate]);

    // Totals for categories without VAT rate (for Box 6/7 completeness)
    const allResult = await pool.query(`
      SELECT
        t.amount,
        COALESCE(c.is_income, CASE WHEN t.amount > 0 THEN true ELSE false END) as is_income
      FROM transactions t
      LEFT JOIN categories c ON t.category_id = c.id
      WHERE t.user_id = $1
        AND t.date >= $2
        AND t.date <= $3
    `, [userId, startDate, endDate]);

    // Calculate VAT boxes
    // Assumption: transaction amounts are VAT-inclusive (gross)
    let outputVat = 0;    // Box 1: VAT on sales
    let inputVat = 0;     // Box 4: VAT on purchases
    let netSales = 0;     // Box 6: net value of sales
    let netPurchases = 0; // Box 7: net value of purchases

    for (const row of result.rows) {
      const gross = Math.abs(parseFloat(row.amount));
      const rate = parseFloat(row.vat_rate);
      const vatAmount = gross - (gross / (1 + rate / 100));
      const netAmount = gross / (1 + rate / 100);

      if (row.is_income) {
        outputVat += vatAmount;
        netSales += netAmount;
      } else {
        inputVat += vatAmount;
        netPurchases += netAmount;
      }
    }

    // Add zero-rated amounts (vat_rate=0) to net totals via the main query rows
    // (they're included above: vatAmount=0 for 0% rate, so net = gross)

    // For Box 6/7 we also include transactions with no category or null vat_rate
    // (these contribute to net figures but no VAT)
    for (const row of allResult.rows) {
      const gross = Math.abs(parseFloat(row.amount));
      // If already counted in VAT rows, skip (check if category has vat_rate)
      // For all-result we include everything — deduplicate by checking if this
      // transaction was VAT-rated (approximation: add non-VAT amounts to box 6/7)
    }
    // Simpler approach: recalculate Box 6/7 from all transactions
    let totalSalesGross = 0;
    let totalPurchasesGross = 0;
    for (const row of allResult.rows) {
      if (row.is_income) {
        totalSalesGross += Math.abs(parseFloat(row.amount));
      } else {
        totalPurchasesGross += Math.abs(parseFloat(row.amount));
      }
    }

    // Recalculate net sales/purchases including non-VATable items (at gross = net)
    // Box 6 = total output net (VAT-rated net + non-VATable gross)
    // More accurate: sum of all sales minus the VAT portion we already calculated
    const box6 = totalSalesGross - outputVat;
    const box7 = totalPurchasesGross - inputVat;

    // HMRC MTD Boxes
    const box1 = Math.max(0, outputVat);      // VAT due on sales
    const box2 = 0;                            // EU acquisitions (post-Brexit = 0)
    const box3 = box1 + box2;                  // Total VAT due
    const box4 = Math.max(0, inputVat);        // VAT reclaimed on purchases
    const box5 = box3 - box4;                  // Net VAT payable (+) or reclaimable (-)

    // Transaction counts
    const countResult = await pool.query(
      `SELECT COUNT(*) as count FROM transactions WHERE user_id = $1 AND date >= $2 AND date <= $3`,
      [userId, startDate, endDate]
    );

    res.json({
      quarter: quarterLabel,
      period: { start: startDate, end: endDate },
      boxes: {
        box1: parseFloat(box1.toFixed(2)),
        box2: parseFloat(box2.toFixed(2)),
        box3: parseFloat(box3.toFixed(2)),
        box4: parseFloat(box4.toFixed(2)),
        box5: parseFloat(box5.toFixed(2)),
        box6: parseFloat(Math.max(0, box6).toFixed(2)),
        box7: parseFloat(Math.max(0, box7).toFixed(2)),
        box8: 0,
        box9: 0,
      },
      summary: {
        output_vat: parseFloat(box1.toFixed(2)),
        input_vat: parseFloat(box4.toFixed(2)),
        net_vat_position: parseFloat(box5.toFixed(2)),
        net_vat_payable: box5 >= 0,
        total_sales_gross: parseFloat(totalSalesGross.toFixed(2)),
        total_purchases_gross: parseFloat(totalPurchasesGross.toFixed(2)),
        transaction_count: parseInt(countResult.rows[0].count),
      }
    });
  } catch (err) {
    console.error('VAT summary error:', err);
    res.status(500).json({ error: 'Failed to calculate VAT summary' });
  }
});

// ═══════════════════════════════════════════════════════════
// VAT LIVE LIABILITY — real-time current-quarter tax estimate
// GET /api/vat/live-liability
// Returns: current quarter liability, quarter progress, prev quarter comparison
// ═══════════════════════════════════════════════════════════

app.get('/api/vat/live-liability', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const now = new Date();

    function getQuarterDates(year, q) {
      const months = {
        1: { start: `${year}-01-01`, end: `${year}-03-31` },
        2: { start: `${year}-04-01`, end: `${year}-06-30` },
        3: { start: `${year}-07-01`, end: `${year}-09-30` },
        4: { start: `${year}-10-01`, end: `${year}-12-31` },
      };
      return months[q];
    }

    async function computeVATForRange(startDate, endDate) {
      const result = await pool.query(`
        SELECT t.amount, c.is_income, COALESCE(t.vat_rate_override, c.vat_rate) AS vat_rate
        FROM transactions t
        JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3 AND COALESCE(t.vat_rate_override, c.vat_rate) IS NOT NULL
      `, [userId, startDate, endDate]);

      let outputVat = 0, inputVat = 0, netSales = 0, netPurchases = 0;
      for (const row of result.rows) {
        const gross = Math.abs(parseFloat(row.amount));
        const rate = parseFloat(row.vat_rate);
        const vatAmount = gross - (gross / (1 + rate / 100));
        if (row.is_income) {
          outputVat += vatAmount;
          netSales += gross / (1 + rate / 100);
        } else {
          inputVat += vatAmount;
          netPurchases += gross / (1 + rate / 100);
        }
      }

      const [txRes, catRes] = await Promise.all([
        pool.query(
          'SELECT COUNT(*) as count FROM transactions WHERE user_id = $1 AND date >= $2 AND date <= $3',
          [userId, startDate, endDate]
        ),
        pool.query(
          'SELECT COUNT(*) as count FROM transactions WHERE user_id = $1 AND date >= $2 AND date <= $3 AND category_id IS NOT NULL',
          [userId, startDate, endDate]
        ),
      ]);

      return {
        output_vat: parseFloat(outputVat.toFixed(2)),
        input_vat: parseFloat(inputVat.toFixed(2)),
        net_liability: parseFloat((outputVat - inputVat).toFixed(2)),
        net_payable: (outputVat - inputVat) >= 0,
        net_sales: parseFloat(Math.max(0, netSales).toFixed(2)),
        net_purchases: parseFloat(Math.max(0, netPurchases).toFixed(2)),
        transaction_count: parseInt(txRes.rows[0].count),
        categorised_count: parseInt(catRes.rows[0].count),
      };
    }

    // Current quarter
    const month = now.getMonth() + 1;
    const q = Math.ceil(month / 3);
    const year = now.getFullYear();
    const { start: startDate, end: endDate } = getQuarterDates(year, q);
    const quarterLabel = `Q${q}-${year}`;

    // Quarter progress
    const qStart = new Date(startDate + 'T00:00:00');
    const qEnd = new Date(endDate + 'T23:59:59');
    const totalDays = Math.round((new Date(endDate + 'T00:00:00') - new Date(startDate + 'T00:00:00')) / (1000 * 60 * 60 * 24)) + 1;
    const daysPassed = Math.max(0, Math.round((now - qStart) / (1000 * 60 * 60 * 24)));
    const daysRemaining = Math.max(0, totalDays - daysPassed);
    const progressPct = Math.min(100, Math.round((daysPassed / totalDays) * 100));

    // Previous quarter
    let prevQ = q - 1;
    let prevYear = year;
    if (prevQ === 0) { prevQ = 4; prevYear = year - 1; }
    const { start: prevStart, end: prevEnd } = getQuarterDates(prevYear, prevQ);
    const prevLabel = `Q${prevQ}-${prevYear}`;

    const [current, prev] = await Promise.all([
      computeVATForRange(startDate, endDate),
      computeVATForRange(prevStart, prevEnd),
    ]);

    // Quarter name (e.g. "Quarter 1 (Jan–Mar)")
    const quarterNames = {
      1: 'Quarter 1 (Jan–Mar)',
      2: 'Quarter 2 (Apr–Jun)',
      3: 'Quarter 3 (Jul–Sep)',
      4: 'Quarter 4 (Oct–Dec)',
    };

    res.json({
      current_quarter: quarterLabel,
      quarter_name: quarterNames[q],
      period: { start: startDate, end: endDate },
      progress: {
        total_days: totalDays,
        days_passed: daysPassed,
        days_remaining: daysRemaining,
        percent: progressPct,
        quarter_number: q,
      },
      liability: current,
      previous_quarter: {
        quarter: prevLabel,
        period: { start: prevStart, end: prevEnd },
        liability: prev,
      },
    });
  } catch (err) {
    console.error('VAT live liability error:', err);
    res.status(500).json({ error: 'Failed to calculate VAT liability' });
  }
});

// POST /api/vat/file — file a VAT return for a quarter (stub: records filing intent)
// Full HMRC MTD API integration is a future feature. This stub records the filing event.
app.post('/api/vat/file', authenticateToken, requireOwner, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { quarter } = req.body; // e.g. 'Q1-2026'
    if (!quarter) return res.status(400).json({ error: 'quarter is required (e.g. Q1-2026)' });

    // Record the filing in our analytics system
    await recordEvent({
      userId,
      sessionId: '',
      eventName: 'vat_return_filed',
      properties: { quarter },
      utmParams: {},
      userAgent: req.get('User-Agent') || '',
      ipAddress: req.ip || req.connection?.remoteAddress || '',
    });

    res.json({ success: true, message: 'VAT return filed', quarter });
  } catch (err) {
    console.error('VAT file error:', err);
    res.status(500).json({ error: 'Failed to file VAT return' });
  }
});

// ═══════════════════════════════════════════════════════════
// CATEGORISATION RULES API
// ═══════════════════════════════════════════════════════════

// GET /api/rules - list all rules for user
app.get('/api/rules', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT r.*, c.name as category_name, c.color as category_color, c.icon as category_icon, c.slug as category_slug
       FROM categorisation_rules r
       JOIN categories c ON r.category_id = c.id
       WHERE r.user_id = $1
       ORDER BY r.created_at DESC`,
      [req.user.userId]
    );
    res.json({ rules: result.rows });
  } catch (err) {
    console.error('Rules fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch rules' });
  }
});

// POST /api/rules - create rule and bulk re-categorise past transactions
app.post('/api/rules', authenticateToken, requireOwner, async (req, res) => {
  try {
    const { merchant_pattern, category_id, vat_rate_override, is_active } = req.body;
    if (!merchant_pattern || !category_id) {
      return res.status(400).json({ error: 'merchant_pattern and category_id are required' });
    }

    const userId = req.user.userId;
    const pattern = merchant_pattern.trim();
    const vatOverride = (vat_rate_override !== undefined && vat_rate_override !== null) ? parseFloat(vat_rate_override) : null;
    const active = is_active !== undefined ? Boolean(is_active) : true;

    // Upsert rule (update category if same merchant already has a rule)
    const ruleResult = await pool.query(
      `INSERT INTO categorisation_rules (user_id, merchant_pattern, category_id, vat_rate_override, is_active)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id, merchant_pattern) DO UPDATE
         SET category_id = EXCLUDED.category_id, vat_rate_override = EXCLUDED.vat_rate_override,
             is_active = EXCLUDED.is_active, updated_at = NOW()
       RETURNING *`,
      [userId, pattern, category_id, vatOverride, active]
    );
    const rule = ruleResult.rows[0];

    // Bulk re-categorise past transactions that match this merchant
    // Match: merchant_name ILIKE pattern (case-insensitive) OR description ILIKE pattern
    const bulkResult = await pool.query(
      `UPDATE transactions
       SET category_id = $1, is_manually_categorised = false, ai_confidence = 1.0, updated_at = NOW()
       WHERE user_id = $2
         AND (merchant_name ILIKE $3 OR (merchant_name IS NULL AND description ILIKE $3))
         AND category_id IS DISTINCT FROM $1
       RETURNING id`,
      [category_id, userId, pattern]
    );

    // Update match count
    await pool.query(
      `UPDATE categorisation_rules SET match_count = $1 WHERE id = $2`,
      [bulkResult.rows.length, rule.id]
    );

    // Fetch full rule with category info
    const fullRule = await pool.query(
      `SELECT r.*, c.name as category_name, c.color as category_color, c.icon as category_icon, c.slug as category_slug
       FROM categorisation_rules r
       JOIN categories c ON r.category_id = c.id
       WHERE r.id = $1`,
      [rule.id]
    );

    // Audit log
    logAudit({
      userId,
      actionType: 'create',
      entityType: 'rule',
      entityId: rule.id,
      oldValue: null,
      newValue: fullRule.rows[0],
      req,
    });

    res.json({
      rule: fullRule.rows[0],
      bulk_updated: bulkResult.rows.length
    });
  } catch (err) {
    console.error('Rules create error:', err);
    res.status(500).json({ error: 'Failed to create rule' });
  }
});

// PATCH /api/rules/:id - update rule (category, is_active toggle, vat_rate_override)
app.patch('/api/rules/:id', authenticateToken, requireOwner, async (req, res) => {
  try {
    const { category_id, is_active, vat_rate_override } = req.body;
    const userId = req.user.userId;

    const oldRes = await pool.query(
      'SELECT * FROM categorisation_rules WHERE id = $1 AND user_id = $2',
      [req.params.id, userId]
    );
    if (!oldRes.rows[0]) return res.status(404).json({ error: 'Rule not found' });
    const existing = oldRes.rows[0];

    const newCategoryId = category_id !== undefined ? category_id : existing.category_id;
    const newIsActive = is_active !== undefined ? Boolean(is_active) : existing.is_active;
    const newVatOverride = vat_rate_override !== undefined ? (vat_rate_override === null ? null : parseFloat(vat_rate_override)) : existing.vat_rate_override;

    const result = await pool.query(
      `UPDATE categorisation_rules
       SET category_id = $1, is_active = $2, vat_rate_override = $3, updated_at = NOW()
       WHERE id = $4 AND user_id = $5
       RETURNING *`,
      [newCategoryId, newIsActive, newVatOverride, req.params.id, userId]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Rule not found' });

    logAudit({
      userId,
      actionType: 'update',
      entityType: 'rule',
      entityId: req.params.id,
      oldValue: oldRes.rows[0] || null,
      newValue: result.rows[0],
      req,
    });

    res.json({ rule: result.rows[0] });
  } catch (err) {
    console.error('Rules update error:', err);
    res.status(500).json({ error: 'Failed to update rule' });
  }
});

// DELETE /api/rules/:id
app.delete('/api/rules/:id', authenticateToken, requireOwner, async (req, res) => {
  try {
    const userId = req.user.userId;

    const oldRes = await pool.query(
      'SELECT * FROM categorisation_rules WHERE id = $1 AND user_id = $2',
      [req.params.id, userId]
    );

    const result = await pool.query(
      `DELETE FROM categorisation_rules WHERE id = $1 AND user_id = $2 RETURNING id`,
      [req.params.id, userId]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Rule not found' });

    logAudit({
      userId,
      actionType: 'delete',
      entityType: 'rule',
      entityId: req.params.id,
      oldValue: oldRes.rows[0] || null,
      newValue: null,
      req,
    });

    res.json({ success: true });
  } catch (err) {
    console.error('Rules delete error:', err);
    res.status(500).json({ error: 'Failed to delete rule' });
  }
});

// ═══════════════════════════════════════════════════════════
// RECEIPTS API
// ═══════════════════════════════════════════════════════════

// ─── Helpers ────────────────────────────────────────────

const nodeFetch = require('node-fetch'); // v2.x — avoids "Unexpected end of form" with native fetch
const FormData = require('form-data');

/**
 * Upload buffer to R2 via Polsia proxy.
 * Returns the CDN URL on success, throws on failure.
 */
async function uploadToR2(buffer, filename, mimeType) {
  const formData = new FormData();
  formData.append('file', buffer, { filename, contentType: mimeType });

  const response = await nodeFetch('https://polsia.com/api/proxy/r2/upload', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.POLSIA_API_KEY}`,
      ...formData.getHeaders(), // CRITICAL: includes Content-Type with multipart boundary
    },
    body: formData,
  });

  const result = await response.json();
  if (!result.success) {
    throw new Error(result.error?.message || `R2 upload failed: ${response.status}`);
  }
  return result.file.url; // https://cdn.polsia.com/<key>
}

/**
 * Run Claude vision OCR on a receipt image.
 * Returns extracted { vendor, date, amount, vat_amount, category_hint }.
 */
async function extractReceiptData(base64Data, mimeType) {
  const prompt = `You are a UK bookkeeping assistant. Extract receipt/invoice details from this image.

Return ONLY a valid JSON object with these fields (use null for any field you cannot find):
{
  "vendor": "business name (string)",
  "date": "ISO date string YYYY-MM-DD or null",
  "amount": total amount as a number (include VAT, decimal e.g. 24.99),
  "vat_amount": VAT amount as a number or null,
  "category_hint": one of: "office_supplies", "travel", "meals_entertainment", "utilities", "software", "professional_services", "marketing", "equipment", "other_expenses"
}

Do not include any explanation — only the JSON.`;

  try {
    const completion = await openai.chat.completions.create({
      model: 'gpt-4o',
      max_tokens: 300,
      messages: [
        {
          role: 'user',
          content: [
            {
              type: 'image_url',
              image_url: { url: `data:${mimeType};base64,${base64Data}` }
            },
            { type: 'text', text: prompt }
          ]
        }
      ],
      task: 'receipt-ocr'
    });

    const content = completion.choices[0].message.content.trim();
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) return JSON.parse(jsonMatch[0]);
    return null;
  } catch (err) {
    console.error('Receipt OCR error:', err.message);
    return null;
  }
}

/**
 * Compute Jaccard token-set similarity between two vendor/merchant strings.
 * Returns 0–1. Returns 0 if either string is empty.
 */
function vendorSimilarity(a, b) {
  if (!a || !b) return 0;
  const normalise = s => s.toLowerCase().replace(/[^a-z0-9\s]/g, '').split(/\s+/).filter(Boolean);
  const setA = new Set(normalise(a));
  const setB = new Set(normalise(b));
  if (!setA.size || !setB.size) return 0;
  let intersection = 0;
  for (const t of setA) if (setB.has(t)) intersection++;
  return intersection / (setA.size + setB.size - intersection); // Jaccard
}

/**
 * Detect and flag potential duplicate transactions for a newly-inserted transaction.
 * Compares against existing non-duplicate transactions within the last 90 days using:
 *   - Exact amount match (within £0.01)          — weight 40%
 *   - Date proximity ±1 day                       — weight 30%
 *   - Vendor/description Jaccard similarity        — weight 30%
 * Inserts into duplicate_pairs (status='pending') when confidence ≥ 0.70.
 */
async function detectAndFlagDuplicates(userId, transactionId) {
  if (!pool) return;
  try {
    const txRes = await pool.query(
      `SELECT id, date, amount, description, merchant_name
       FROM transactions
       WHERE id = $1 AND user_id = $2
         AND (is_duplicate IS NULL OR is_duplicate = false)`,
      [transactionId, userId]
    );
    if (!txRes.rows.length) return;
    const tx = txRes.rows[0];

    const candidates = await pool.query(
      `SELECT id, date, amount, description, merchant_name
       FROM transactions
       WHERE user_id = $1
         AND id != $2
         AND ABS(amount::decimal - $3::decimal) < 0.01
         AND ABS(date::date - $4::date) <= 1
         AND date >= NOW() - INTERVAL '90 days'
         AND (is_duplicate IS NULL OR is_duplicate = false)`,
      [userId, transactionId, tx.amount, tx.date]
    );

    for (const cand of candidates.rows) {
      const daysDiff    = Math.abs(new Date(tx.date) - new Date(cand.date)) / 86400000;
      const dateScore   = Math.max(0, 1 - daysDiff);
      const vendorScore = vendorSimilarity(
        tx.merchant_name   || tx.description   || '',
        cand.merchant_name || cand.description || ''
      );
      // Amount always matches (within £0.01 → score 1.0)
      const confidence = Math.round((0.4 + 0.3 * dateScore + 0.3 * vendorScore) * 1000) / 1000;
      if (confidence >= 0.7) {
        const id1 = Math.min(transactionId, cand.id);
        const id2 = Math.max(transactionId, cand.id);
        await pool.query(
          `INSERT INTO duplicate_pairs
             (user_id, transaction_id_1, transaction_id_2, match_reason, match_score, status)
           VALUES ($1, $2, $3, 'fuzzy_match', $4, 'pending')
           ON CONFLICT (transaction_id_1, transaction_id_2) DO NOTHING`,
          [userId, id1, id2, confidence]
        );
      }
    }
  } catch (err) {
    console.error('detectAndFlagDuplicates error:', err.message);
  }
}

/**
 * Find candidate transactions matching a receipt (amount ±£1, date ±3 days).
 * Scores each candidate (amount 50%, date 30%, vendor 20%) and returns top 3 ranked by confidence.
 * Accepts optional vendor string for fuzzy name matching.
 */
async function findMatchingTransactions(userId, amount, date, vendor = null) {
  if (!amount || !date) return [];
  try {
    const result = await pool.query(
      `SELECT id, description, merchant_name, amount, date
       FROM transactions
       WHERE user_id = $1
         AND ABS(ABS(amount) - $2) <= 1.00
         AND ABS(date - $3::date) <= 3
         AND amount < 0
         AND id NOT IN (SELECT matched_transaction_id FROM receipts WHERE user_id = $1 AND matched_transaction_id IS NOT NULL)
       ORDER BY ABS(ABS(amount) - $2), ABS(date - $3::date)
       LIMIT 10`,
      [userId, parseFloat(amount), date]
    );

    const receiptAmt = parseFloat(amount);
    const receiptDate = new Date(date);

    const scored = result.rows.map(tx => {
      const amtDiff = Math.abs(Math.abs(parseFloat(tx.amount)) - receiptAmt);
      const amtScore = Math.max(0, 1 - amtDiff / 1.00);

      const txDate = new Date(tx.date);
      const daysDiff = Math.abs((txDate - receiptDate) / 86400000);
      const dateScore = Math.max(0, 1 - daysDiff / 3);

      const vendorName = tx.merchant_name || tx.description || '';
      const vScore = vendor ? vendorSimilarity(vendor, vendorName) : 0;

      const confidence = Math.round((0.5 * amtScore + 0.3 * dateScore + 0.2 * vScore) * 100) / 100;
      const confidence_label = confidence >= 0.8 ? 'high' : confidence >= 0.5 ? 'medium' : 'low';

      return { ...tx, confidence, confidence_label };
    });

    scored.sort((a, b) => b.confidence - a.confidence);
    return scored.slice(0, 3);
  } catch (err) {
    console.error('Match transaction error:', err.message);
    return [];
  }
}

// GET /api/receipts — list receipts for the authenticated user
// ?status=matched|unmatched|needs_review|all  (default: all)
app.get('/api/receipts', authenticateToken, async (req, res) => {
  try {
    const { status } = req.query;
    let statusFilter = '';
    const params = [req.user.userId];

    if (status === 'matched') {
      statusFilter = ' AND r.matched_transaction_id IS NOT NULL';
    } else if (status === 'unmatched') {
      statusFilter = " AND r.matched_transaction_id IS NULL AND r.status != 'needs_review'";
    } else if (status === 'needs_review') {
      statusFilter = " AND r.status = 'needs_review'";
    }

    const result = await pool.query(
      `SELECT r.*, c.name as category_name, c.color as category_color, c.icon as category_icon,
              t.description as matched_tx_description, t.date as matched_tx_date,
              t.amount as matched_tx_amount, t.merchant_name as matched_tx_merchant
       FROM receipts r
       LEFT JOIN categories c ON r.category_id = c.id
       LEFT JOIN transactions t ON r.matched_transaction_id = t.id
       WHERE r.user_id = $1${statusFilter}
       ORDER BY r.created_at DESC`,
      params
    );
    res.json({ receipts: result.rows });
  } catch (err) {
    console.error('Receipts fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch receipts' });
  }
});

// POST /api/receipts/upload — upload receipt image, run OCR, auto-match
app.post('/api/receipts/upload', authenticateToken, requireOwner, async (req, res) => {
  try {
    const { fileData, fileName, mimeType } = req.body;

    // Validate
    if (!fileData || !fileName) {
      return res.status(400).json({ error: 'fileData and fileName are required' });
    }

    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'application/pdf'];
    const fileMime = mimeType || 'image/jpeg';
    if (!allowedTypes.includes(fileMime)) {
      return res.status(400).json({ error: 'Unsupported file type. Use JPEG, PNG, WebP, or PDF.' });
    }

    // Decode base64
    const base64 = fileData.includes(',') ? fileData.split(',')[1] : fileData;
    const buffer = Buffer.from(base64, 'base64');

    if (buffer.length > 15 * 1024 * 1024) {
      return res.status(400).json({ error: 'File too large. Max 15MB.' });
    }

    // Store file via R2 proxy (Render filesystem is ephemeral — no local fallback)
    const fileUrl = await uploadToR2(buffer, fileName, fileMime);

    // OCR extraction (skip for PDF without vision support)
    let extracted = null;
    if (fileMime !== 'application/pdf') {
      extracted = await extractReceiptData(base64, fileMime);
    }

    // Auto-match to transaction
    let matchedTxId = null;
    let matchConfidence = null;
    let receiptStatus = extracted ? 'extracted' : 'pending';
    let matchCandidates = [];

    if (extracted?.amount && extracted?.date) {
      matchCandidates = await findMatchingTransactions(req.user.userId, extracted.amount, extracted.date, extracted.vendor || null);
      if (matchCandidates.length === 1 && matchCandidates[0].confidence >= 0.85) {
        // Single high-confidence match — auto-link
        matchedTxId = matchCandidates[0].id;
        matchConfidence = 'auto';
        receiptStatus = 'matched';
      } else if (matchCandidates.length > 0) {
        // Candidates found — surface for user confirmation
        receiptStatus = 'needs_review';
      }
    }

    // Resolve category from hint
    let categoryId = null;
    if (extracted?.category_hint) {
      const catResult = await pool.query(
        `SELECT id FROM categories WHERE slug = $1 LIMIT 1`,
        [extracted.category_hint]
      );
      categoryId = catResult.rows[0]?.id || null;
    }

    // Save to DB
    const insertResult = await pool.query(
      `INSERT INTO receipts (user_id, file_url, original_filename, vendor, date, amount, vat_amount,
                             category_id, status, matched_transaction_id, match_confidence, extracted_data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING *`,
      [
        req.user.userId,
        fileUrl,
        fileName,
        extracted?.vendor || null,
        extracted?.date || null,
        extracted?.amount || null,
        extracted?.vat_amount || null,
        categoryId,
        receiptStatus,
        matchedTxId,
        matchConfidence,
        extracted ? JSON.stringify(extracted) : null
      ]
    );

    const newReceipt = insertResult.rows[0];

    // Sync transactions.receipt_id on auto-match
    if (matchedTxId) {
      await pool.query(
        `UPDATE transactions SET receipt_id = $1 WHERE id = $2 AND user_id = $3`,
        [newReceipt.id, matchedTxId, req.user.userId]
      );
    }

    logAudit({
      userId: req.user.userId,
      actionType: 'create',
      entityType: 'receipt',
      entityId: newReceipt.id,
      oldValue: null,
      newValue: { ...newReceipt, file_url: newReceipt.file_url },
      req,
    });

    res.json({
      receipt: newReceipt,
      extracted,
      matched: matchedTxId !== null,
      // Always return candidates so UI can show the match panel
      match_candidates: matchCandidates.length > 0 && !matchedTxId ? matchCandidates : undefined
    });
  } catch (err) {
    console.error('Receipt upload error:', err);
    res.status(500).json({ error: 'Failed to upload receipt' });
  }
});

// DELETE /api/receipts/:id
app.delete('/api/receipts/:id', authenticateToken, requireOwner, async (req, res) => {
  try {
    const userId = req.user.userId;

    const oldRes = await pool.query(
      'SELECT * FROM receipts WHERE id = $1 AND user_id = $2',
      [req.params.id, userId]
    );

    // Clear transactions.receipt_id before deleting (FK ON DELETE SET NULL handles it but let's be explicit)
    if (oldRes.rows[0]?.matched_transaction_id) {
      await pool.query(
        `UPDATE transactions SET receipt_id = NULL WHERE id = $1 AND user_id = $2`,
        [oldRes.rows[0].matched_transaction_id, userId]
      );
    }

    const result = await pool.query(
      `DELETE FROM receipts WHERE id = $1 AND user_id = $2 RETURNING id`,
      [req.params.id, userId]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Receipt not found' });

    logAudit({
      userId,
      actionType: 'delete',
      entityType: 'receipt',
      entityId: req.params.id,
      oldValue: oldRes.rows[0] || null,
      newValue: null,
      req,
    });

    res.json({ success: true });
  } catch (err) {
    console.error('Receipt delete error:', err);
    res.status(500).json({ error: 'Failed to delete receipt' });
  }
});

// POST /api/receipts/:id/match — manually link receipt to a transaction
app.post('/api/receipts/:id/match', authenticateToken, requireOwner, async (req, res) => {
  try {
    const userId = req.user.userId;
    const receiptId = parseInt(req.params.id);
    const { transaction_id } = req.body;

    if (!transaction_id) return res.status(400).json({ error: 'transaction_id is required' });

    // Verify receipt belongs to user
    const receiptCheck = await pool.query(
      'SELECT id FROM receipts WHERE id = $1 AND user_id = $2',
      [receiptId, userId]
    );
    if (!receiptCheck.rows[0]) return res.status(404).json({ error: 'Receipt not found' });

    // Verify transaction belongs to user
    const txCheck = await pool.query(
      'SELECT id, description, merchant_name, amount, date FROM transactions WHERE id = $1 AND user_id = $2',
      [transaction_id, userId]
    );
    if (!txCheck.rows[0]) return res.status(404).json({ error: 'Transaction not found' });

    // Update receipt
    const updated = await pool.query(
      `UPDATE receipts
       SET matched_transaction_id = $1, match_confidence = 'manual', status = 'matched', updated_at = NOW()
       WHERE id = $2 AND user_id = $3
       RETURNING *`,
      [transaction_id, receiptId, userId]
    );

    // Sync transactions.receipt_id
    await pool.query(
      `UPDATE transactions SET receipt_id = $1 WHERE id = $2 AND user_id = $3`,
      [receiptId, transaction_id, userId]
    );

    logAudit({ userId, actionType: 'update', entityType: 'receipt', entityId: receiptId,
      oldValue: { matched_transaction_id: null }, newValue: { matched_transaction_id: transaction_id, match_confidence: 'manual' }, req });
    logAuditEvent({
      userId,
      eventType: 'receipt_matched',
      entityType: 'receipt',
      entityId: receiptId,
      details: { transaction_id, match_confidence: 'manual' },
      req,
    });

    res.json({ receipt: updated.rows[0], transaction: txCheck.rows[0] });
  } catch (err) {
    console.error('Receipt match error:', err);
    res.status(500).json({ error: 'Failed to match receipt' });
  }
});

// POST /api/receipts/:id/link — Phase 2: confirm a suggested match (same semantics as /match)
app.post('/api/receipts/:id/link', authenticateToken, requireOwner, async (req, res) => {
  try {
    const userId = req.user.userId;
    const receiptId = parseInt(req.params.id);
    const { transaction_id } = req.body;

    if (!transaction_id) return res.status(400).json({ error: 'transaction_id is required' });

    const receiptCheck = await pool.query(
      'SELECT id FROM receipts WHERE id = $1 AND user_id = $2',
      [receiptId, userId]
    );
    if (!receiptCheck.rows[0]) return res.status(404).json({ error: 'Receipt not found' });

    const txCheck = await pool.query(
      'SELECT id, description, merchant_name, amount, date FROM transactions WHERE id = $1 AND user_id = $2',
      [transaction_id, userId]
    );
    if (!txCheck.rows[0]) return res.status(404).json({ error: 'Transaction not found' });

    const updated = await pool.query(
      `UPDATE receipts
       SET matched_transaction_id = $1, match_confidence = 'manual', status = 'matched', updated_at = NOW()
       WHERE id = $2 AND user_id = $3
       RETURNING *`,
      [transaction_id, receiptId, userId]
    );

    await pool.query(
      `UPDATE transactions SET receipt_id = $1 WHERE id = $2 AND user_id = $3`,
      [receiptId, transaction_id, userId]
    );

    logAudit({ userId, actionType: 'update', entityType: 'receipt', entityId: receiptId,
      oldValue: { matched_transaction_id: null }, newValue: { matched_transaction_id: transaction_id, match_confidence: 'manual' }, req });
    logAuditEvent({
      userId,
      eventType: 'receipt_matched',
      entityType: 'receipt',
      entityId: receiptId,
      details: { transaction_id, match_confidence: 'manual', source: 'link' },
      req,
    });

    res.json({ receipt: updated.rows[0], transaction: txCheck.rows[0] });
  } catch (err) {
    console.error('Receipt link error:', err);
    res.status(500).json({ error: 'Failed to link receipt' });
  }
});

// POST /api/receipts/:id/unmatch — detach receipt from transaction
app.post('/api/receipts/:id/unmatch', authenticateToken, requireOwner, async (req, res) => {
  try {
    const userId = req.user.userId;
    const receiptId = parseInt(req.params.id);

    const receiptCheck = await pool.query(
      'SELECT id, matched_transaction_id FROM receipts WHERE id = $1 AND user_id = $2',
      [receiptId, userId]
    );
    if (!receiptCheck.rows[0]) return res.status(404).json({ error: 'Receipt not found' });

    const updated = await pool.query(
      `UPDATE receipts
       SET matched_transaction_id = NULL, match_confidence = NULL, status = 'extracted', updated_at = NOW()
       WHERE id = $1 AND user_id = $2
       RETURNING *`,
      [receiptId, userId]
    );

    // Clear transactions.receipt_id
    if (receiptCheck.rows[0].matched_transaction_id) {
      await pool.query(
        `UPDATE transactions SET receipt_id = NULL WHERE id = $1 AND user_id = $2`,
        [receiptCheck.rows[0].matched_transaction_id, userId]
      );
    }

    logAudit({ userId, actionType: 'update', entityType: 'receipt', entityId: receiptId,
      oldValue: { matched_transaction_id: receiptCheck.rows[0].matched_transaction_id },
      newValue: { matched_transaction_id: null }, req });

    res.json({ receipt: updated.rows[0] });
  } catch (err) {
    console.error('Receipt unmatch error:', err);
    res.status(500).json({ error: 'Failed to unmatch receipt' });
  }
});

// GET /api/receipts/:id/matches — return top 3 candidate transactions ranked by confidence
app.get('/api/receipts/:id/matches', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const receiptId = parseInt(req.params.id);

    const receiptResult = await pool.query(
      'SELECT id, vendor, amount, date FROM receipts WHERE id = $1 AND user_id = $2',
      [receiptId, userId]
    );
    if (!receiptResult.rows[0]) return res.status(404).json({ error: 'Receipt not found' });

    const r = receiptResult.rows[0];
    const matches = await findMatchingTransactions(userId, r.amount, r.date, r.vendor);

    res.json({ receipt_id: receiptId, matches });
  } catch (err) {
    console.error('Receipt matches error:', err);
    res.status(500).json({ error: 'Failed to fetch matches' });
  }
});

// GET /api/receipts/candidates — find transaction candidates for a given amount/date
app.get('/api/receipts/candidates', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { amount, date, search } = req.query;

    let query = `
      SELECT t.id, t.description, t.merchant_name, t.amount, t.date,
             c.name as category_name, c.color as category_color, c.icon as category_icon
      FROM transactions t
      LEFT JOIN categories c ON t.category_id = c.id
      WHERE t.user_id = $1
        AND t.amount < 0
        AND t.id NOT IN (
          SELECT matched_transaction_id FROM receipts
          WHERE user_id = $1 AND matched_transaction_id IS NOT NULL
        )
    `;
    const params = [userId];
    let pIdx = 2;

    if (search) {
      query += ` AND (t.description ILIKE $${pIdx} OR t.merchant_name ILIKE $${pIdx})`;
      params.push(`%${search}%`);
      pIdx++;
    }
    if (amount) {
      query += ` AND ABS(ABS(t.amount) - $${pIdx}) <= 5.00`;
      params.push(parseFloat(amount));
      pIdx++;
    }
    if (date) {
      query += ` AND ABS(t.date - $${pIdx}::date) <= 7`;
      params.push(date);
      pIdx++;
    }

    query += ` ORDER BY t.date DESC LIMIT 50`;
    const result = await pool.query(query, params);
    res.json({ transactions: result.rows });
  } catch (err) {
    console.error('Candidates error:', err);
    res.status(500).json({ error: 'Failed to fetch candidates' });
  }
});

// ═══════════════════════════════════════════════════════════
// TEAM MEMBERS API
// ═══════════════════════════════════════════════════════════

// GET /api/team/members — list team members for the authenticated owner
app.get('/api/team/members', authenticateToken, requireOwner, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, role, invited_at, accepted_at
       FROM team_members WHERE owner_id = $1 ORDER BY invited_at DESC`,
      [req.user.userId]
    );
    res.json({ members: result.rows });
  } catch (err) {
    console.error('Team members fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch team members' });
  }
});

// POST /api/team/invite — invite an accountant/team member
app.post('/api/team/invite', authenticateToken, requireOwner, async (req, res) => {
  try {
    const { email, role = 'accountant' } = req.body;
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email is required' });
    }
    const normalised = email.toLowerCase().trim();
    const inviteToken = crypto.randomBytes(48).toString('hex');
    const appUrl = process.env.APP_URL || 'https://finowl.co.uk';

    // Check if already invited
    const existing = await pool.query(
      `SELECT id, invite_token, accepted_at FROM team_members WHERE owner_id = $1 AND LOWER(email) = $2`,
      [req.user.userId, normalised]
    );
    if (existing.rows.length > 0) {
      const member = existing.rows[0];
      if (member.accepted_at) {
        return res.status(409).json({ error: 'This person has already accepted an invite for your account.' });
      }
      // Re-send invite (update token)
      await pool.query(
        `UPDATE team_members SET invite_token = $1, invited_at = NOW() WHERE id = $2`,
        [inviteToken, member.id]
      );
      const inviteUrl = `${appUrl}/accept?token=${inviteToken}`;
      return res.json({ success: true, invite_url: inviteUrl, resent: true });
    }

    const result = await pool.query(
      `INSERT INTO team_members (owner_id, email, role, invite_token)
       VALUES ($1, $2, $3, $4) RETURNING id, email, role, invited_at`,
      [req.user.userId, normalised, role, inviteToken]
    );

    const inviteUrl = `${appUrl}/accept?token=${inviteToken}`;

    // Send invite email via email.js utility (best-effort, don't fail if unavailable)
    const ownerEmail = req.user.email;
    await sendInviteEmail({ to: normalised, ownerEmail, inviteUrl }).catch(
      (err) => console.warn('[Team] Invite email send failed (non-fatal):', err.message)
    );

    res.json({
      success: true,
      member: result.rows[0],
      invite_url: inviteUrl
    });
  } catch (err) {
    console.error('Team invite error:', err);
    res.status(500).json({ error: 'Failed to create invite' });
  }
});

// DELETE /api/team/members/:id — remove a team member
app.delete('/api/team/members/:id', authenticateToken, requireOwner, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM team_members WHERE id = $1 AND owner_id = $2 RETURNING id`,
      [req.params.id, req.user.userId]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Team member not found' });
    res.json({ success: true });
  } catch (err) {
    console.error('Team member delete error:', err);
    res.status(500).json({ error: 'Failed to remove team member' });
  }
});

// GET /api/team/accept — accept a team invite (no auth required — uses invite token)
app.get('/api/team/accept', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'Invite token is required' });

    const memberResult = await pool.query(
      `SELECT tm.*, u.email as owner_email
       FROM team_members tm
       JOIN users u ON tm.owner_id = u.id
       WHERE tm.invite_token = $1`,
      [token]
    );
    if (!memberResult.rows[0]) {
      return res.status(404).json({ error: 'Invite not found or already used' });
    }

    const member = memberResult.rows[0];

    // Mark as accepted
    await pool.query(
      `UPDATE team_members SET accepted_at = COALESCE(accepted_at, NOW()) WHERE id = $1`,
      [member.id]
    );

    // Issue a JWT token scoped to the owner's account with accountant role
    const jwtToken = jwt.sign(
      {
        userId: member.owner_id,
        email: member.email,
        role: 'accountant',
        teamMemberId: member.id,
        ownerEmail: member.owner_email
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      token: jwtToken,
      user: {
        email: member.email,
        role: 'accountant',
        ownerEmail: member.owner_email
      }
    });
  } catch (err) {
    console.error('Team accept error:', err);
    res.status(500).json({ error: 'Failed to accept invite' });
  }
});

// ─── Accept page ────────────────────────────────────────
app.get('/accept', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'accept.html'));
});

// ═══════════════════════════════════════════════════════════
// EXPORT API — CSV downloads + Print HTML (PDF via browser)
// ═══════════════════════════════════════════════════════════

function escapeCSV(v) {
  if (v === null || v === undefined) return '';
  const s = String(v);
  return (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r'))
    ? '"' + s.replace(/"/g, '""') + '"'
    : s;
}
function rowToCSV(arr) { return arr.map(escapeCSV).join(','); }
function fmtDate(d) { return d ? String(d).substring(0, 10) : ''; }
function fmtGBP(n) { return n !== null && n !== undefined ? Number(n).toFixed(2) : '0.00'; }

function parseQuarterParam(quarter) {
  const qm = { 1: ['01-01','03-31'], 2: ['04-01','06-30'], 3: ['07-01','09-30'], 4: ['10-01','12-31'] };
  if (quarter) {
    const match = quarter.match(/^Q([1-4])-(\d{4})$/);
    if (!match) return null;
    const qn = parseInt(match[1]), year = parseInt(match[2]);
    return { startDate: `${year}-${qm[qn][0]}`, endDate: `${year}-${qm[qn][1]}`, quarterLabel: quarter };
  }
  const now = new Date(), year = now.getFullYear(), qn = Math.ceil((now.getMonth() + 1) / 3);
  return { startDate: `${year}-${qm[qn][0]}`, endDate: `${year}-${qm[qn][1]}`, quarterLabel: `Q${qn}-${year}` };
}

async function calcVATBoxesForExport(userId, startDate, endDate) {
  const vatRows = await pool.query(
    `SELECT t.amount, c.is_income, COALESCE(t.vat_rate_override, c.vat_rate) AS vat_rate FROM transactions t
     JOIN categories c ON t.category_id = c.id
     WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3 AND COALESCE(t.vat_rate_override, c.vat_rate) IS NOT NULL`,
    [userId, startDate, endDate]
  );
  const allRows = await pool.query(
    `SELECT t.amount, COALESCE(c.is_income, CASE WHEN t.amount > 0 THEN true ELSE false END) as is_income
     FROM transactions t LEFT JOIN categories c ON t.category_id = c.id
     WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3`,
    [userId, startDate, endDate]
  );
  let outputVat = 0, inputVat = 0;
  for (const r of vatRows.rows) {
    const gross = Math.abs(parseFloat(r.amount));
    const vat = gross - gross / (1 + parseFloat(r.vat_rate) / 100);
    if (r.is_income) outputVat += vat; else inputVat += vat;
  }
  let totalSales = 0, totalPurchases = 0;
  for (const r of allRows.rows) {
    const g = Math.abs(parseFloat(r.amount));
    if (r.is_income) totalSales += g; else totalPurchases += g;
  }
  const box1 = Math.max(0, outputVat), box4 = Math.max(0, inputVat);
  return {
    box1, box2: 0, box3: box1, box4, box5: box1 - box4,
    box6: Math.max(0, totalSales - box1), box7: Math.max(0, totalPurchases - box4),
    box8: 0, box9: 0
  };
}

function printLayout(title, bodyHtml) {
  const now = new Date().toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' });
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>${title} — FinOwl</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=DM+Sans:wght@400;500&display=swap" rel="stylesheet">
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'DM Sans',sans-serif;color:#0a0f1a;background:#fff;padding:2rem;max-width:920px;margin:0 auto;font-size:0.9rem;line-height:1.5}
  h1,h2,h3,h4{font-family:'Space Grotesk',sans-serif}
  .print-header{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2.5px solid #0a0f1a;padding-bottom:1rem;margin-bottom:1.5rem}
  .logo{display:flex;align-items:center;gap:0.5rem}
  .logo-circle{width:34px;height:34px;background:#d4920b;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1.1rem;flex-shrink:0}
  .logo-name{font-family:'Space Grotesk',sans-serif;font-weight:700;font-size:1.3rem}
  .header-right{text-align:right;font-size:0.8rem;color:#6b7280}
  h1{font-size:1.5rem;margin-bottom:0.25rem;margin-top:0}
  .meta{font-size:0.8rem;color:#6b7280;margin-bottom:1.5rem}
  .summary-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:0.75rem;margin-bottom:1.5rem}
  .sum-box{border:1px solid #e5e2db;border-radius:8px;padding:0.85rem 1rem}
  .sum-label{font-size:0.72rem;color:#6b7280;margin-bottom:0.2rem}
  .sum-val{font-size:1.35rem;font-weight:700;font-family:'Space Grotesk',sans-serif}
  .section-title{font-size:0.72rem;font-weight:600;text-transform:uppercase;letter-spacing:0.07em;color:#6b7280;margin:1.5rem 0 0.6rem;padding-top:1rem;border-top:1px solid #f0ede8}
  table{width:100%;border-collapse:collapse;margin-bottom:1rem;font-size:0.87rem}
  thead th{text-align:left;padding:0.45rem 0.65rem;border-bottom:2px solid #e5e2db;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05em;color:#6b7280;white-space:nowrap}
  td{padding:0.4rem 0.65rem;border-bottom:1px solid #f0ede8;vertical-align:middle}
  .num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
  .total-row td{border-top:2px solid #0a0f1a;font-weight:600;padding-top:0.55rem;background:#faf9f6}
  .highlight{background:#fef3c7!important}
  .pos{color:#2d6a4f} .neg{color:#c0392b}
  .footer{margin-top:2rem;padding-top:1rem;border-top:1px solid #e5e2db;font-size:0.72rem;color:#9ca3af;display:flex;justify-content:space-between}
  .no-print{margin-bottom:1rem}
  @media print{
    body{padding:0.75rem}
    .no-print{display:none!important}
    a{color:inherit;text-decoration:none}
    thead{display:table-header-group}
    tr{page-break-inside:avoid}
  }
</style></head>
<body>
<div class="no-print" style="background:#fef3c7;border:1px solid #fde68a;border-radius:8px;padding:0.6rem 1rem;font-size:0.82rem;display:flex;align-items:center;gap:0.75rem">
  🖨 <strong>Ready to print.</strong> Use your browser's print dialog to save as PDF. &nbsp;
  <button onclick="window.print()" style="background:#d4920b;color:#fff;border:none;border-radius:6px;padding:0.35rem 0.85rem;cursor:pointer;font-family:inherit;font-weight:600;font-size:0.82rem">Print / Save PDF</button>
  <button onclick="window.close()" style="background:none;border:1px solid #ccc;border-radius:6px;padding:0.35rem 0.85rem;cursor:pointer;font-family:inherit;font-size:0.82rem">Close</button>
</div>
<div class="print-header">
  <div class="logo">
    <div class="logo-circle">🦉</div>
    <div class="logo-name">FinOwl</div>
  </div>
  <div class="header-right">
    <div style="font-weight:600;font-size:0.9rem">${title}</div>
    <div>Generated: ${now}</div>
    <div style="margin-top:0.2rem">finowl.co.uk</div>
  </div>
</div>
${bodyHtml}
<div class="footer">
  <div>FinOwl — UK Business Bookkeeping · finowl.co.uk</div>
  <div>Generated ${now}</div>
</div>
<script>setTimeout(()=>window.print(),600);</script>
</body></html>`;
}

// ─── GET /api/export/transactions.csv ──────────────────────
app.get('/api/export/transactions.csv', authenticateTokenFromQuery, async (req, res) => {
  try {
    const { category, startDate, endDate, search } = req.query;
    let q = `SELECT t.date, t.description, t.merchant_name, t.amount, c.name as category_name,
                    t.original_currency, t.original_amount, t.exchange_rate
             FROM transactions t LEFT JOIN categories c ON t.category_id = c.id
             WHERE t.user_id = $1`;
    const params = [req.user.userId]; let idx = 2;
    if (category && category !== 'all') { q += ` AND c.slug = $${idx++}`; params.push(category); }
    if (startDate) { q += ` AND t.date >= $${idx++}`; params.push(startDate); }
    if (endDate)   { q += ` AND t.date <= $${idx++}`; params.push(endDate); }
    if (search)    { q += ` AND (t.description ILIKE $${idx} OR t.merchant_name ILIKE $${idx})`; params.push(`%${search}%`); idx++; }
    q += ' ORDER BY t.date DESC, t.id DESC';
    const result = await pool.query(q, params);
    const lines = [rowToCSV(['Date', 'Description', 'Merchant', 'Amount (GBP)', 'Category', 'Type', 'Original Currency', 'Original Amount', 'Exchange Rate'])];
    for (const r of result.rows) {
      lines.push(rowToCSV([
        fmtDate(r.date), r.description || '', r.merchant_name || '',
        fmtGBP(r.amount), r.category_name || 'Uncategorised',
        parseFloat(r.amount) > 0 ? 'Income' : 'Expense',
        r.original_currency || '',
        r.original_amount ? parseFloat(r.original_amount).toFixed(2) : '',
        r.exchange_rate ? parseFloat(r.exchange_rate).toFixed(6) : ''
      ]));
    }
    const fname = `finowl-transactions-${new Date().toISOString().substring(0, 10)}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    res.setHeader('Cache-Control', 'no-store');
    res.send('\uFEFF' + lines.join('\r\n'));
  } catch (err) {
    console.error('Export transactions error:', err);
    res.status(500).send('Export failed');
  }
});

// ─── GET /api/export/vat-summary.csv ───────────────────────
app.get('/api/export/vat-summary.csv', authenticateTokenFromQuery, async (req, res) => {
  try {
    const userId = req.user.userId;
    const parsed = parseQuarterParam(req.query.quarter);
    if (!parsed) return res.status(400).send('Invalid quarter format. Use Q1-2026');
    const { startDate, endDate, quarterLabel } = parsed;
    const boxes = await calcVATBoxesForExport(userId, startDate, endDate);
    const userRes = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
    const vatRes = await pool.query('SELECT vat_number FROM vat_settings WHERE user_id = $1', [userId]);
    const userEmail = userRes.rows[0]?.email || '';
    const vatNum = vatRes.rows[0]?.vat_number || '';

    const lines = [
      rowToCSV(['FinOwl VAT Summary Export']),
      rowToCSV([`Generated: ${new Date().toLocaleDateString('en-GB')}`]),
      rowToCSV([`Quarter: ${quarterLabel}`]),
      rowToCSV([`Period: ${startDate} to ${endDate}`]),
      rowToCSV([`Account: ${userEmail}`]),
      ...(vatNum ? [rowToCSV([`VAT Number: ${vatNum}`])] : []),
      '',
      rowToCSV(['HMRC VAT Return Boxes', '', '']),
      rowToCSV(['Box', 'Description', 'Amount (GBP)']),
      rowToCSV(['Box 1', 'VAT due on sales (output tax)', fmtGBP(boxes.box1)]),
      rowToCSV(['Box 2', 'VAT due on EU acquisitions', '0.00']),
      rowToCSV(['Box 3', 'Total VAT due (Box 1 + Box 2)', fmtGBP(boxes.box3)]),
      rowToCSV(['Box 4', 'VAT reclaimed on purchases (input tax)', fmtGBP(boxes.box4)]),
      rowToCSV(['Box 5', `Net VAT ${boxes.box5 >= 0 ? 'payable' : 'reclaimable'}`, fmtGBP(boxes.box5)]),
      rowToCSV(['Box 6', 'Total net value of sales (ex-VAT)', fmtGBP(boxes.box6)]),
      rowToCSV(['Box 7', 'Total net value of purchases (ex-VAT)', fmtGBP(boxes.box7)]),
      rowToCSV(['Box 8', 'EU supplies of goods', '0.00']),
      rowToCSV(['Box 9', 'EU acquisitions of goods', '0.00']),
      '',
    ];
    const txRows = await pool.query(
      `SELECT t.date, t.description, t.merchant_name, t.amount, c.name as category_name, c.vat_rate, c.is_income
       FROM transactions t LEFT JOIN categories c ON t.category_id = c.id
       WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3
       ORDER BY t.date DESC, t.id DESC`,
      [userId, startDate, endDate]
    );
    lines.push(rowToCSV(['Transaction Detail', '', '', '', '', '', '']));
    lines.push(rowToCSV(['Date', 'Description', 'Merchant', 'Amount (GBP)', 'Category', 'VAT Rate', 'Type']));
    for (const r of txRows.rows) {
      lines.push(rowToCSV([
        fmtDate(r.date), r.description || '', r.merchant_name || '',
        fmtGBP(r.amount), r.category_name || 'Uncategorised',
        r.vat_rate !== null ? r.vat_rate + '%' : 'Exempt/N/A',
        r.is_income ? 'Income' : 'Expense'
      ]));
    }
    const fname = `finowl-vat-${quarterLabel}-${new Date().toISOString().substring(0, 10)}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    res.setHeader('Cache-Control', 'no-store');
    res.send('\uFEFF' + lines.join('\r\n'));
  } catch (err) {
    console.error('Export VAT CSV error:', err);
    res.status(500).send('Export failed');
  }
});

// ─── GET /api/export/pl-report.csv ─────────────────────────
app.get('/api/export/pl-report.csv', authenticateTokenFromQuery, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { startDate, endDate } = req.query;
    const params = [userId]; let idx = 2;
    let df = '';
    if (startDate) { df += ` AND t.date >= $${idx++}`; params.push(startDate); }
    if (endDate)   { df += ` AND t.date <= $${idx++}`; params.push(endDate); }

    const totalsRes = await pool.query(
      `SELECT COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END),0) as income,
              COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END),0) as expenses,
              COALESCE(SUM(amount),0) as net
       FROM transactions t WHERE user_id = $1 ${df}`, params
    );
    const catRes = await pool.query(
      `SELECT c.name,
              COALESCE(SUM(CASE WHEN t.amount > 0 THEN t.amount ELSE 0 END),0) as income,
              COALESCE(SUM(CASE WHEN t.amount < 0 THEN ABS(t.amount) ELSE 0 END),0) as expenses,
              COUNT(t.id) as tx_count
       FROM transactions t JOIN categories c ON t.category_id = c.id
       WHERE t.user_id = $1 ${df}
       GROUP BY c.id, c.name ORDER BY expenses DESC`, params
    );
    const monthlyRes = await pool.query(
      `SELECT TO_CHAR(date,'YYYY-MM') as month,
              COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END),0) as income,
              COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END),0) as expenses
       FROM transactions t WHERE user_id = $1 ${df}
       GROUP BY TO_CHAR(date,'YYYY-MM') ORDER BY month`, params
    );
    const userRes = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
    const t0 = totalsRes.rows[0];

    const lines = [
      rowToCSV(['FinOwl Profit & Loss Export']),
      rowToCSV([`Generated: ${new Date().toLocaleDateString('en-GB')}`]),
      rowToCSV([`Account: ${userRes.rows[0]?.email || ''}`]),
      ...(startDate ? [rowToCSV([`Period from: ${startDate}`])] : []),
      ...(endDate   ? [rowToCSV([`Period to: ${endDate}`])]   : []),
      '',
      rowToCSV(['SUMMARY', '']),
      rowToCSV(['Total Income', fmtGBP(t0.income)]),
      rowToCSV(['Total Expenses', fmtGBP(t0.expenses)]),
      rowToCSV(['Net Profit', fmtGBP(t0.net)]),
      '',
      rowToCSV(['CATEGORY BREAKDOWN', '', '', '']),
      rowToCSV(['Category', 'Income (GBP)', 'Expenses (GBP)', 'Transactions']),
    ];
    for (const r of catRes.rows) {
      lines.push(rowToCSV([r.name, fmtGBP(r.income), fmtGBP(r.expenses), r.tx_count]));
    }
    lines.push('');
    lines.push(rowToCSV(['MONTHLY BREAKDOWN', '', '', '']));
    lines.push(rowToCSV(['Month', 'Income (GBP)', 'Expenses (GBP)', 'Net (GBP)']));
    for (const r of monthlyRes.rows) {
      lines.push(rowToCSV([r.month, fmtGBP(r.income), fmtGBP(r.expenses), fmtGBP(parseFloat(r.income) - parseFloat(r.expenses))]));
    }
    const fname = `finowl-pl-report-${new Date().toISOString().substring(0, 10)}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    res.setHeader('Cache-Control', 'no-store');
    res.send('\uFEFF' + lines.join('\r\n'));
  } catch (err) {
    console.error('Export P&L error:', err);
    res.status(500).send('Export failed');
  }
});

// ─── GET /print/vat-summary ─────────────────────────────────
app.get('/print/vat-summary', authenticateTokenFromQuery, async (req, res) => {
  try {
    const userId = req.user.userId;
    const parsed = parseQuarterParam(req.query.quarter);
    if (!parsed) return res.status(400).send('Invalid quarter');
    const { startDate, endDate, quarterLabel } = parsed;
    const boxes = await calcVATBoxesForExport(userId, startDate, endDate);
    const userRes = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
    const vatRes = await pool.query('SELECT vat_number FROM vat_settings WHERE user_id = $1', [userId]);
    const vatNum = vatRes.rows[0]?.vat_number || '';
    const userEmail = userRes.rows[0]?.email || '';

    const body = `
      <h1>VAT Return — ${quarterLabel}</h1>
      <div class="meta">
        Period: ${startDate} to ${endDate}
        ${vatNum ? ' &nbsp;|&nbsp; VAT No: ' + vatNum : ''}
        &nbsp;|&nbsp; ${userEmail}
      </div>
      <p class="section-title" style="border-top:none;margin-top:0">HMRC VAT Return Boxes</p>
      <table>
        <thead><tr><th>Box</th><th>Description</th><th class="num">Amount</th></tr></thead>
        <tbody>
          <tr><td>Box 1</td><td>VAT due on sales (output tax)</td><td class="num">£${fmtGBP(boxes.box1)}</td></tr>
          <tr><td>Box 2</td><td>VAT due on EU acquisitions</td><td class="num">£0.00</td></tr>
          <tr><td>Box 3</td><td>Total VAT due (Box 1 + Box 2)</td><td class="num"><strong>£${fmtGBP(boxes.box3)}</strong></td></tr>
          <tr><td>Box 4</td><td>VAT reclaimed on purchases (input tax)</td><td class="num pos">£${fmtGBP(boxes.box4)}</td></tr>
          <tr class="total-row highlight">
            <td>Box 5</td>
            <td>Net VAT ${boxes.box5 >= 0 ? 'payable to HMRC' : 'reclaimable from HMRC'}</td>
            <td class="num ${boxes.box5 >= 0 ? 'neg' : 'pos'}"><strong>£${fmtGBP(Math.abs(boxes.box5))}</strong></td>
          </tr>
          <tr><td>Box 6</td><td>Total value of sales (ex-VAT)</td><td class="num">£${fmtGBP(boxes.box6)}</td></tr>
          <tr><td>Box 7</td><td>Total value of purchases (ex-VAT)</td><td class="num">£${fmtGBP(boxes.box7)}</td></tr>
          <tr><td>Box 8</td><td>EU supplies of goods (ex-VAT)</td><td class="num">£0.00</td></tr>
          <tr><td>Box 9</td><td>EU acquisitions of goods (ex-VAT)</td><td class="num">£0.00</td></tr>
        </tbody>
      </table>
      <p style="font-size:0.78rem;color:#6b7280;margin-top:0.5rem">
        Generated from FinOwl transaction data. UK standard rate scheme (VAT-inclusive transactions).
        Verify against your accounting records before filing with HMRC.
      </p>
    `;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.send(printLayout(`VAT Return ${quarterLabel}`, body));
  } catch (err) {
    console.error('Print VAT error:', err);
    res.status(500).send('Print failed');
  }
});

// ─── GET /print/pl-report ───────────────────────────────────
app.get('/print/pl-report', authenticateTokenFromQuery, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { startDate, endDate } = req.query;
    const params = [userId]; let idx = 2;
    let df = '';
    if (startDate) { df += ` AND t.date >= $${idx++}`; params.push(startDate); }
    if (endDate)   { df += ` AND t.date <= $${idx++}`; params.push(endDate); }

    const totalsRes = await pool.query(
      `SELECT COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END),0) as income,
              COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END),0) as expenses,
              COALESCE(SUM(amount),0) as net
       FROM transactions t WHERE user_id = $1 ${df}`, params
    );
    const catRes = await pool.query(
      `SELECT c.name, c.icon, c.is_income,
              COALESCE(SUM(CASE WHEN t.amount > 0 THEN t.amount ELSE 0 END),0) as income,
              COALESCE(SUM(CASE WHEN t.amount < 0 THEN ABS(t.amount) ELSE 0 END),0) as expenses,
              COUNT(t.id) as tx_count
       FROM transactions t JOIN categories c ON t.category_id = c.id
       WHERE t.user_id = $1 ${df}
       GROUP BY c.id, c.name, c.icon, c.is_income ORDER BY c.is_income DESC, expenses DESC`, params
    );
    const monthlyRes = await pool.query(
      `SELECT TO_CHAR(date,'YYYY-MM') as month,
              COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END),0) as income,
              COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END),0) as expenses
       FROM transactions t WHERE user_id = $1 ${df}
       GROUP BY TO_CHAR(date,'YYYY-MM') ORDER BY month`, params
    );
    const userRes = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
    const t0 = totalsRes.rows[0];
    const net = parseFloat(t0.net);
    const incomeRows = catRes.rows.filter(r => parseFloat(r.income) > 0);
    const expenseRows = catRes.rows.filter(r => parseFloat(r.expenses) > 0);
    const filterDesc = [startDate ? `From ${startDate}` : '', endDate ? `To ${endDate}` : ''].filter(Boolean).join(' · ');

    const body = `
      <h1>Profit &amp; Loss Report</h1>
      <div class="meta">${filterDesc ? filterDesc + ' &nbsp;|&nbsp; ' : ''}${userRes.rows[0]?.email || ''}</div>
      <div class="summary-grid">
        <div class="sum-box">
          <div class="sum-label">Total Income</div>
          <div class="sum-val pos">£${fmtGBP(t0.income)}</div>
        </div>
        <div class="sum-box">
          <div class="sum-label">Total Expenses</div>
          <div class="sum-val neg">£${fmtGBP(t0.expenses)}</div>
        </div>
        <div class="sum-box" style="border-color:${net>=0?'#d8f3dc':'#fde8e8'};background:${net>=0?'#f0faf2':'#fff5f5'}">
          <div class="sum-label">Net Profit</div>
          <div class="sum-val ${net>=0?'pos':'neg'}">£${fmtGBP(net)}</div>
        </div>
      </div>
      <p class="section-title">Income Breakdown</p>
      <table>
        <thead><tr><th>Category</th><th class="num">Income</th><th class="num">Transactions</th></tr></thead>
        <tbody>
          ${incomeRows.map(r=>`<tr><td>${r.icon||''} ${r.name}</td><td class="num pos">£${fmtGBP(r.income)}</td><td class="num">${r.tx_count}</td></tr>`).join('')}
          ${incomeRows.length===0?'<tr><td colspan="3" style="color:#9ca3af;text-align:center">No income recorded</td></tr>':''}
          <tr class="total-row"><td>Total Income</td><td class="num pos">£${fmtGBP(t0.income)}</td><td></td></tr>
        </tbody>
      </table>
      <p class="section-title">Expense Breakdown</p>
      <table>
        <thead><tr><th>Category</th><th class="num">Expenses</th><th class="num">Transactions</th></tr></thead>
        <tbody>
          ${expenseRows.map(r=>`<tr><td>${r.icon||''} ${r.name}</td><td class="num neg">£${fmtGBP(r.expenses)}</td><td class="num">${r.tx_count}</td></tr>`).join('')}
          ${expenseRows.length===0?'<tr><td colspan="3" style="color:#9ca3af;text-align:center">No expenses recorded</td></tr>':''}
          <tr class="total-row"><td>Total Expenses</td><td class="num neg">£${fmtGBP(t0.expenses)}</td><td></td></tr>
        </tbody>
      </table>
      <p class="section-title">Monthly Summary</p>
      <table>
        <thead><tr><th>Month</th><th class="num">Income</th><th class="num">Expenses</th><th class="num">Net</th></tr></thead>
        <tbody>
          ${monthlyRes.rows.map(r=>{const mn=parseFloat(r.income)-parseFloat(r.expenses);return`<tr><td>${r.month}</td><td class="num pos">£${fmtGBP(r.income)}</td><td class="num neg">£${fmtGBP(r.expenses)}</td><td class="num ${mn>=0?'pos':'neg'}">£${fmtGBP(mn)}</td></tr>`;}).join('')}
          ${monthlyRes.rows.length===0?'<tr><td colspan="4" style="color:#9ca3af;text-align:center">No data</td></tr>':''}
        </tbody>
      </table>
    `;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.send(printLayout('Profit & Loss Report', body));
  } catch (err) {
    console.error('Print P&L error:', err);
    res.status(500).send('Print failed');
  }
});

// ─── GET /print/transactions ────────────────────────────────
app.get('/print/transactions', authenticateTokenFromQuery, async (req, res) => {
  try {
    const { category, startDate, endDate, search } = req.query;
    let q = `SELECT t.date, t.description, t.merchant_name, t.amount, c.name as category_name, c.icon as category_icon
             FROM transactions t LEFT JOIN categories c ON t.category_id = c.id
             WHERE t.user_id = $1`;
    const params = [req.user.userId]; let idx = 2;
    if (category && category !== 'all') { q += ` AND c.slug = $${idx++}`; params.push(category); }
    if (startDate) { q += ` AND t.date >= $${idx++}`; params.push(startDate); }
    if (endDate)   { q += ` AND t.date <= $${idx++}`; params.push(endDate); }
    if (search)    { q += ` AND (t.description ILIKE $${idx} OR t.merchant_name ILIKE $${idx})`; params.push(`%${search}%`); idx++; }
    q += ' ORDER BY t.date DESC, t.id DESC LIMIT 500';
    const result = await pool.query(q, params);
    const userRes = await pool.query('SELECT email FROM users WHERE id = $1', [req.user.userId]);
    const userEmail = userRes.rows[0]?.email || '';
    const totalIncome = result.rows.reduce((s,r)=>s+(parseFloat(r.amount)>0?parseFloat(r.amount):0), 0);
    const totalExpenses = result.rows.reduce((s,r)=>s+(parseFloat(r.amount)<0?Math.abs(parseFloat(r.amount)):0), 0);
    const filterDesc = [
      startDate ? `From ${startDate}` : '', endDate ? `To ${endDate}` : '',
      category && category !== 'all' ? `Category: ${category}` : '',
      search ? `Search: "${search}"` : ''
    ].filter(Boolean).join(' · ');

    const body = `
      <h1>Transactions</h1>
      <div class="meta">${filterDesc ? filterDesc + ' &nbsp;|&nbsp; ' : ''}${result.rows.length} transactions &nbsp;|&nbsp; ${userEmail}</div>
      <div style="display:flex;gap:0.75rem;margin-bottom:1.5rem">
        <div style="flex:1;border:1px solid #d8f3dc;background:#f0faf2;border-radius:8px;padding:0.75rem 1rem">
          <div style="font-size:0.72rem;color:#6b7280">Total Income</div>
          <div style="font-weight:700;color:#2d6a4f;font-family:'Space Grotesk',sans-serif">£${fmtGBP(totalIncome)}</div>
        </div>
        <div style="flex:1;border:1px solid #fde8e8;background:#fff5f5;border-radius:8px;padding:0.75rem 1rem">
          <div style="font-size:0.72rem;color:#6b7280">Total Expenses</div>
          <div style="font-weight:700;color:#c0392b;font-family:'Space Grotesk',sans-serif">£${fmtGBP(totalExpenses)}</div>
        </div>
      </div>
      <table>
        <thead><tr><th>Date</th><th>Description</th><th>Category</th><th class="num">Amount</th></tr></thead>
        <tbody>
          ${result.rows.map(r=>`
            <tr>
              <td style="white-space:nowrap">${fmtDate(r.date)}</td>
              <td>${r.description || ''}</td>
              <td style="font-size:0.82rem;white-space:nowrap">${r.category_icon||''} ${r.category_name||'Uncategorised'}</td>
              <td class="num ${parseFloat(r.amount)>0?'pos':'neg'}">£${fmtGBP(Math.abs(parseFloat(r.amount)))}</td>
            </tr>`).join('')}
        </tbody>
      </table>
      ${result.rows.length===500?'<p style="font-size:0.78rem;color:#9ca3af">Showing first 500 transactions. Use date filters to narrow the range.</p>':''}
    `;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.send(printLayout('Transactions', body));
  } catch (err) {
    console.error('Print transactions error:', err);
    res.status(500).send('Print failed');
  }
});

// ═══════════════════════════════════════════════════════════
// AUDIT LOG API — HMRC Compliance Trail
// Append-only — all financial changes are permanently logged
// ═══════════════════════════════════════════════════════════

// GET /api/audit-logs — query audit trail with filters
app.get('/api/audit-logs', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { startDate, endDate, actionType, entityType, limit = 100, offset = 0 } = req.query;

    let filterConditions = ['al.user_id = $1'];
    let filterParams = [userId];
    let p = 2;

    if (startDate)  { filterConditions.push(`al.created_at >= $${p++}`); filterParams.push(startDate); }
    if (endDate)    { filterConditions.push(`al.created_at < ($${p++}::date + INTERVAL '1 day')`); filterParams.push(endDate); }
    if (actionType) { filterConditions.push(`al.action_type = $${p++}`); filterParams.push(actionType); }
    if (entityType) { filterConditions.push(`al.entity_type = $${p++}`); filterParams.push(entityType); }

    const where = filterConditions.join(' AND ');

    const [result, countResult] = await Promise.all([
      pool.query(
        `SELECT al.*, u.email as user_email
         FROM audit_log al
         JOIN users u ON al.user_id = u.id
         WHERE ${where}
         ORDER BY al.created_at DESC
         LIMIT $${p} OFFSET $${p + 1}`,
        [...filterParams, parseInt(limit) || 100, parseInt(offset) || 0]
      ),
      pool.query(
        `SELECT COUNT(*) as total FROM audit_log al WHERE ${where}`,
        filterParams
      ),
    ]);

    res.json({ success: true, logs: result.rows, total: parseInt(countResult.rows[0].total) });
  } catch (err) {
    console.error('Audit log fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

// GET /api/audit-logs/export — download full audit trail as CSV (accepts ?token= for browser downloads)
app.get('/api/audit-logs/export', authenticateTokenFromQuery, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { startDate, endDate, actionType, entityType } = req.query;

    let filterConditions = ['al.user_id = $1'];
    let filterParams = [userId];
    let p = 2;

    if (startDate)  { filterConditions.push(`al.created_at >= $${p++}`); filterParams.push(startDate); }
    if (endDate)    { filterConditions.push(`al.created_at < ($${p++}::date + INTERVAL '1 day')`); filterParams.push(endDate); }
    if (actionType) { filterConditions.push(`al.action_type = $${p++}`); filterParams.push(actionType); }
    if (entityType) { filterConditions.push(`al.entity_type = $${p++}`); filterParams.push(entityType); }

    const result = await pool.query(
      `SELECT al.*, u.email as user_email
       FROM audit_log al
       JOIN users u ON al.user_id = u.id
       WHERE ${filterConditions.join(' AND ')}
       ORDER BY al.created_at DESC
       LIMIT 50000`,
      filterParams
    );

    const userRes = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
    const userEmail = userRes.rows[0]?.email || '';

    // Build CSV
    const lines = [
      rowToCSV(['FinOwl HMRC Audit Trail Export']),
      rowToCSV([`Generated: ${new Date().toLocaleDateString('en-GB')} ${new Date().toLocaleTimeString('en-GB')}`]),
      rowToCSV([`Account: ${userEmail}`]),
      rowToCSV([`Records: ${result.rows.length}`]),
      '',
      rowToCSV(['Timestamp (UTC)', 'User', 'Action', 'Record Type', 'Record ID', 'Before Change', 'After Change']),
    ];

    for (const log of result.rows) {
      lines.push(rowToCSV([
        new Date(log.created_at).toISOString(),
        log.user_email,
        log.action_type.toUpperCase(),
        log.entity_type,
        log.entity_id,
        log.old_value ? JSON.stringify(log.old_value) : '',
        log.new_value ? JSON.stringify(log.new_value) : '',
      ]));
    }

    const fname = `finowl-audit-trail-${new Date().toISOString().substring(0, 10)}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    res.setHeader('Cache-Control', 'no-store');
    res.send('\uFEFF' + lines.join('\r\n'));
  } catch (err) {
    console.error('Audit log export error:', err);
    res.status(500).json({ error: 'Failed to export audit logs' });
  }
});

// ─── YEAR-END TAX SUMMARY ───────────────────────────────

// Helper: get UK tax year date range
// year=2026 → tax year 2025/26 (6 Apr 2025 – 5 Apr 2026)
function taxYearDates(year) {
  const y = parseInt(year);
  if (!y || y < 2000 || y > 2100) return null;
  return {
    startDate: `${y - 1}-04-06`,
    endDate:   `${y}-04-05`,
    label:     `${y - 1}/${String(y).slice(2)}`,
    year:      y,
  };
}

// UK Income Tax + NI calculation (2024/25 onwards bands)
function calcUKTax(netProfit) {
  const PERSONAL_ALLOWANCE = 12570;
  const BASIC_LIMIT        = 50270;   // threshold (PA + basic band)
  const HIGHER_LIMIT       = 125140;
  const BASIC_RATE         = 0.20;
  const HIGHER_RATE        = 0.40;
  const ADDITIONAL_RATE    = 0.45;
  const NI_LOWER           = 12570;
  const NI_UPPER           = 50270;
  const NI_RATE_LOWER      = 0.06;   // Class 4 NI lower (6% from Apr 2024)
  const NI_RATE_UPPER      = 0.02;   // Class 4 NI upper (2%)

  const profit = Math.max(0, netProfit);

  // Taper personal allowance above £100k (reduce by £1 for every £2 over £100k)
  let pa = PERSONAL_ALLOWANCE;
  if (profit > 100000) pa = Math.max(0, PERSONAL_ALLOWANCE - Math.floor((profit - 100000) / 2));

  // Income Tax
  const taxable = Math.max(0, profit - pa);
  const basicTaxable    = Math.max(0, Math.min(taxable, BASIC_LIMIT - PERSONAL_ALLOWANCE));
  const higherTaxable   = Math.max(0, Math.min(taxable - basicTaxable, HIGHER_LIMIT - BASIC_LIMIT));
  const additionalTaxable = Math.max(0, taxable - basicTaxable - higherTaxable);

  const basicTax      = basicTaxable * BASIC_RATE;
  const higherTax     = higherTaxable * HIGHER_RATE;
  const additionalTax = additionalTaxable * ADDITIONAL_RATE;
  const totalIncomeTax = basicTax + higherTax + additionalTax;

  // Class 4 NI (no Class 2 from April 2024)
  const ni4Lower = Math.max(0, Math.min(profit, NI_UPPER) - NI_LOWER) * NI_RATE_LOWER;
  const ni4Upper = Math.max(0, profit - NI_UPPER) * NI_RATE_UPPER;
  const totalNI  = ni4Lower + ni4Upper;

  const totalTax      = totalIncomeTax + totalNI;
  const effectiveRate = profit > 0 ? (totalTax / profit) * 100 : 0;

  // Payments on account (if total SA tax bill > £1,000)
  const poaRequired  = totalTax > 1000;
  const poaEachPayment = poaRequired ? totalTax / 2 : 0;

  return {
    personalAllowance: pa,
    basicTaxable,    basicTax,
    higherTaxable,   higherTax,
    additionalTaxable, additionalTax,
    totalIncomeTax,
    ni4Lower: Math.max(0, Math.min(profit, NI_UPPER) - NI_LOWER),
    ni4LowerTax: ni4Lower,
    ni4Upper: Math.max(0, profit - NI_UPPER),
    ni4UpperTax: ni4Upper,
    totalNI,
    totalTax,
    effectiveRate,
    poaRequired,
    poaEachPayment,
  };
}

// GET /api/year-end/summary?year=2026
app.get('/api/year-end/summary', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const tyd = taxYearDates(req.query.year || new Date().getFullYear());
    if (!tyd) return res.status(400).json({ error: 'Invalid year parameter' });

    const { startDate, endDate } = tyd;

    // 1. Totals from transactions
    const totalsRes = await pool.query(`
      SELECT
        COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) AS income,
        COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) AS expenses,
        COALESCE(SUM(amount), 0) AS net,
        COUNT(*) AS tx_count,
        COUNT(CASE WHEN category_id IS NULL THEN 1 END) AS uncat_count
      FROM transactions
      WHERE user_id = $1 AND date >= $2 AND date <= $3
    `, [userId, startDate, endDate]);

    // 2. Income by category
    const incomeRes = await pool.query(`
      SELECT c.name, c.icon, c.color,
        COALESCE(SUM(t.amount), 0) AS total,
        COUNT(t.id) AS tx_count
      FROM transactions t
      JOIN categories c ON t.category_id = c.id
      WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3 AND t.amount > 0
      GROUP BY c.id, c.name, c.icon, c.color
      ORDER BY total DESC
    `, [userId, startDate, endDate]);

    // 3. Expense categories
    const expenseRes = await pool.query(`
      SELECT c.name, c.icon, c.color,
        COALESCE(SUM(ABS(t.amount)), 0) AS total,
        COUNT(t.id) AS tx_count
      FROM transactions t
      JOIN categories c ON t.category_id = c.id
      WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3 AND t.amount < 0
      GROUP BY c.id, c.name, c.icon, c.color
      ORDER BY total DESC
    `, [userId, startDate, endDate]);

    // 4. Monthly data
    const monthlyRes = await pool.query(`
      SELECT
        TO_CHAR(date, 'YYYY-MM') AS month,
        COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) AS income,
        COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) AS expenses
      FROM transactions
      WHERE user_id = $1 AND date >= $2 AND date <= $3
      GROUP BY TO_CHAR(date, 'YYYY-MM')
      ORDER BY month
    `, [userId, startDate, endDate]);

    // 5. Mileage deduction
    let mileageDeduction = 0, mileageMiles = 0;
    try {
      const milRes = await pool.query(`
        SELECT miles FROM mileage_trips
        WHERE user_id = $1 AND date >= $2 AND date <= $3 ORDER BY date
      `, [userId, startDate, endDate]);
      let cumMiles = 0;
      for (const row of milRes.rows) {
        const m = parseFloat(row.miles);
        const firstBucket = Math.max(0, Math.min(m, Math.max(0, 10000 - cumMiles)));
        const secondBucket = m - firstBucket;
        mileageDeduction += firstBucket * 0.45 + secondBucket * 0.25;
        cumMiles += m;
        mileageMiles += m;
      }
    } catch (_) { /* table may not have data */ }

    // 6. Manual expenses (allowable only)
    let manualExpensesTotal = 0;
    try {
      const manualRes = await pool.query(`
        SELECT COALESCE(SUM(amount), 0) AS total
        FROM manual_expenses
        WHERE user_id = $1 AND date >= $2 AND date <= $3 AND is_allowable = true
      `, [userId, startDate, endDate]);
      manualExpensesTotal = parseFloat(manualRes.rows[0]?.total || 0);
    } catch (_) { /* table may not have data */ }

    // 7. Prior year comparison
    const priorTyd = taxYearDates(tyd.year - 1);
    let priorYear = null;
    if (priorTyd) {
      try {
        const priorRes = await pool.query(`
          SELECT
            COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) AS income,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) AS expenses,
            COALESCE(SUM(amount), 0) AS net,
            COUNT(*) AS tx_count
          FROM transactions
          WHERE user_id = $1 AND date >= $2 AND date <= $3
        `, [userId, priorTyd.startDate, priorTyd.endDate]);
        const pr = priorRes.rows[0];
        if (parseFloat(pr.tx_count) > 0) {
          priorYear = {
            income:   parseFloat(pr.income),
            expenses: parseFloat(pr.expenses),
            net:      parseFloat(pr.net),
            label:    priorTyd.label,
          };
        }
      } catch (_) { /* no data */ }
    }

    // 8. SA settings (business name etc)
    let saSettings = null;
    try {
      const saRes = await pool.query('SELECT * FROM sa_settings WHERE user_id = $1', [userId]);
      saSettings = saRes.rows[0] || null;
    } catch (_) {}

    const t0 = totalsRes.rows[0];
    const grossIncome  = parseFloat(t0.income);
    const grossExpenses = parseFloat(t0.expenses);
    const txNetProfit   = parseFloat(t0.net);
    const adjustedNet   = txNetProfit + mileageDeduction - manualExpensesTotal;
    // Adjusted net: bank transactions profit PLUS mileage allowance MINUS manual allowable expenses
    // (mileage is deductible from income; manual_expenses are additional deductions)
    const netProfit = txNetProfit - manualExpensesTotal - mileageDeduction;
    // Actually: netProfit = income - bank_expenses - manual_allowable_expenses - mileage_deduction
    const actualNetProfit = grossIncome - grossExpenses - manualExpensesTotal - mileageDeduction;

    const taxCalc = calcUKTax(Math.max(0, actualNetProfit));

    // Key dates
    const filingDeadline = `${tyd.year + 1}-01-31`;
    const poa1Deadline   = `${tyd.year + 1}-01-31`;
    const poa2Deadline   = `${tyd.year + 1}-07-31`;
    const balancingPayment = `${tyd.year + 1}-01-31`;

    res.json({
      taxYear: tyd.label,
      year: tyd.year,
      startDate,
      endDate,
      saSettings,
      // Financial summary
      grossIncome,
      grossExpenses,
      mileageDeduction: parseFloat(mileageDeduction.toFixed(2)),
      mileageMiles: parseFloat(mileageMiles.toFixed(2)),
      manualExpensesTotal: parseFloat(manualExpensesTotal.toFixed(2)),
      netProfit: parseFloat(actualNetProfit.toFixed(2)),
      txCount: parseInt(t0.tx_count),
      uncatCount: parseInt(t0.uncat_count),
      // Tax calculation
      taxBreakdown: taxCalc,
      // Breakdowns
      incomeByCategory:  incomeRes.rows.map(r => ({ ...r, total: parseFloat(r.total), tx_count: parseInt(r.tx_count) })),
      expenseByCategory: expenseRes.rows.map(r => ({ ...r, total: parseFloat(r.total), tx_count: parseInt(r.tx_count) })),
      monthlyData:       monthlyRes.rows.map(r => ({ ...r, income: parseFloat(r.income), expenses: parseFloat(r.expenses) })),
      // Key dates
      keyDates: {
        taxYearEnd:         endDate,
        filingDeadlineOnline: filingDeadline,
        balancingPayment,
        poa1: poa1Deadline,
        poa2: poa2Deadline,
      },
      // Year-over-year
      priorYear,
    });
  } catch (err) {
    console.error('Year-end summary error:', err);
    res.status(500).json({ error: 'Failed to load year-end summary' });
  }
});

// ═══════════════════════════════════════════════════════════
// TAX SUMMARY — Full year-end tax summary with HMRC 2025/26 rates
// GET /api/tax-summary/:taxYear  (e.g. /api/tax-summary/2026 = 2025/26 year)
// ═══════════════════════════════════════════════════════════
app.get('/api/tax-summary/:taxYear', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const tyd = taxYearDates(req.params.taxYear);
    if (!tyd) return res.status(400).json({ error: 'Invalid taxYear. Use a year between 2000–2100, e.g. 2026 for the 2025/26 tax year.' });

    const { startDate, endDate } = tyd;

    // 1. Transaction totals
    const totalsRes = await pool.query(`
      SELECT
        COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) AS income,
        COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) AS expenses,
        COALESCE(SUM(amount), 0) AS net,
        COUNT(*) AS tx_count,
        COUNT(CASE WHEN category_id IS NULL THEN 1 END) AS uncat_count
      FROM transactions
      WHERE user_id = $1 AND date >= $2 AND date <= $3
    `, [userId, startDate, endDate]);

    // 2. Income by category
    const incomeRes = await pool.query(`
      SELECT c.name, c.icon, c.color,
        COALESCE(SUM(t.amount), 0) AS total, COUNT(t.id) AS tx_count
      FROM transactions t
      JOIN categories c ON t.category_id = c.id
      WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3 AND t.amount > 0
      GROUP BY c.id, c.name, c.icon, c.color ORDER BY total DESC
    `, [userId, startDate, endDate]);

    // 3. Expense by category
    const expenseRes = await pool.query(`
      SELECT c.name, c.icon, c.color,
        COALESCE(SUM(ABS(t.amount)), 0) AS total, COUNT(t.id) AS tx_count
      FROM transactions t
      JOIN categories c ON t.category_id = c.id
      WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3 AND t.amount < 0
      GROUP BY c.id, c.name, c.icon, c.color ORDER BY total DESC
    `, [userId, startDate, endDate]);

    // 4. Monthly breakdown
    const monthlyRes = await pool.query(`
      SELECT
        TO_CHAR(date, 'YYYY-MM') AS month,
        COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) AS income,
        COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) AS expenses
      FROM transactions
      WHERE user_id = $1 AND date >= $2 AND date <= $3
      GROUP BY TO_CHAR(date, 'YYYY-MM') ORDER BY month
    `, [userId, startDate, endDate]);

    // 5. Mileage deduction (HMRC advisory rates)
    let mileageDeduction = 0, mileageMiles = 0;
    try {
      const milRes = await pool.query(`SELECT miles FROM mileage_trips WHERE user_id=$1 AND date>=$2 AND date<=$3 ORDER BY date`, [userId, startDate, endDate]);
      let cum = 0;
      for (const row of milRes.rows) {
        const m = parseFloat(row.miles);
        const first  = Math.max(0, Math.min(m, Math.max(0, 10000 - cum)));
        const second = m - first;
        mileageDeduction += first * 0.45 + second * 0.25;
        cum += m; mileageMiles += m;
      }
    } catch (_) {}

    // 6. Manual allowable expenses
    let manualExpensesTotal = 0;
    try {
      const mr = await pool.query(`SELECT COALESCE(SUM(amount),0) AS total FROM manual_expenses WHERE user_id=$1 AND date>=$2 AND date<=$3 AND is_allowable=true`, [userId, startDate, endDate]);
      manualExpensesTotal = parseFloat(mr.rows[0]?.total || 0);
    } catch (_) {}

    // 7. VAT collected vs paid (tax year period)
    let vatCollected = 0, vatPaid = 0;
    try {
      const vatRes = await pool.query(`
        SELECT
          t.amount,
          COALESCE(c.is_income, CASE WHEN t.amount > 0 THEN true ELSE false END) AS is_income,
          COALESCE(t.vat_rate_override, c.vat_rate) AS vat_rate
        FROM transactions t
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3
          AND COALESCE(t.vat_rate_override, c.vat_rate) IS NOT NULL
          AND COALESCE(t.vat_rate_override, c.vat_rate) > 0
      `, [userId, startDate, endDate]);
      for (const row of vatRes.rows) {
        const gross = Math.abs(parseFloat(row.amount));
        const rate = parseFloat(row.vat_rate);
        const vatAmt = gross - (gross / (1 + rate / 100));
        if (row.is_income) vatCollected += vatAmt;
        else vatPaid += vatAmt;
      }
    } catch (_) {}

    // 8. Prior year comparison
    const priorTyd = taxYearDates(tyd.year - 1);
    let priorYear = null;
    if (priorTyd) {
      try {
        const pr = await pool.query(`
          SELECT COALESCE(SUM(CASE WHEN amount>0 THEN amount ELSE 0 END),0) AS income,
                 COALESCE(SUM(CASE WHEN amount<0 THEN ABS(amount) ELSE 0 END),0) AS expenses,
                 COALESCE(SUM(amount),0) AS net, COUNT(*) AS tx_count
          FROM transactions WHERE user_id=$1 AND date>=$2 AND date<=$3
        `, [userId, priorTyd.startDate, priorTyd.endDate]);
        if (parseFloat(pr.rows[0].tx_count) > 0) {
          priorYear = { income: parseFloat(pr.rows[0].income), expenses: parseFloat(pr.rows[0].expenses), net: parseFloat(pr.rows[0].net), label: priorTyd.label };
        }
      } catch (_) {}
    }

    // 9. SA settings
    let saSettings = null;
    try {
      const sa = await pool.query('SELECT * FROM sa_settings WHERE user_id=$1', [userId]);
      saSettings = sa.rows[0] || null;
    } catch (_) {}

    const t0 = totalsRes.rows[0];
    const grossIncome   = parseFloat(t0.income);
    const grossExpenses = parseFloat(t0.expenses);
    const netProfit     = grossIncome - grossExpenses - manualExpensesTotal - mileageDeduction;
    const taxCalc       = calcUKTax(Math.max(0, netProfit));

    // HMRC 2025/26 rate labels
    const rateInfo = {
      personalAllowance: 12570,
      basicRateBand: '£12,571–£50,270',
      higherRateBand: '£50,271–£125,140',
      additionalRateBand: 'Above £125,140',
      ni4LowerBand: '£12,570–£50,270',
      ni4UpperBand: 'Above £50,270',
      taxYear: tyd.label,
    };

    res.json({
      // Meta
      taxYear: tyd.label,
      year: tyd.year,
      startDate,
      endDate,
      saSettings,
      rateInfo,
      // Financials
      grossIncome,
      grossExpenses,
      mileageDeduction: parseFloat(mileageDeduction.toFixed(2)),
      mileageMiles:     parseFloat(mileageMiles.toFixed(2)),
      manualExpensesTotal: parseFloat(manualExpensesTotal.toFixed(2)),
      netProfit:        parseFloat(netProfit.toFixed(2)),
      txCount:          parseInt(t0.tx_count),
      uncatCount:       parseInt(t0.uncat_count),
      // VAT
      vatCollected:     parseFloat(vatCollected.toFixed(2)),
      vatPaid:          parseFloat(vatPaid.toFixed(2)),
      vatNetPosition:   parseFloat((vatCollected - vatPaid).toFixed(2)),
      // Tax calculations (HMRC 2025/26)
      taxBreakdown: taxCalc,
      // Breakdowns
      incomeByCategory:  incomeRes.rows.map(r => ({ ...r, total: parseFloat(r.total), tx_count: parseInt(r.tx_count) })),
      expenseByCategory: expenseRes.rows.map(r => ({ ...r, total: parseFloat(r.total), tx_count: parseInt(r.tx_count) })),
      monthlyData:       monthlyRes.rows.map(r => ({ ...r, income: parseFloat(r.income), expenses: parseFloat(r.expenses) })),
      // Key dates
      keyDates: {
        taxYearEnd:              endDate,
        filingDeadlineOnline:    `${tyd.year + 1}-01-31`,
        balancingPayment:        `${tyd.year + 1}-01-31`,
        poa1:                    `${tyd.year + 1}-01-31`,
        poa2:                    `${tyd.year + 1}-07-31`,
      },
      priorYear,
      // Disclaimer
      disclaimer: 'These are estimates based on your FinOwl data using HMRC ' + tyd.label + ' rates. Consult a qualified accountant before filing your Self Assessment.',
    });
  } catch (err) {
    console.error('Tax summary error:', err);
    res.status(500).json({ error: 'Failed to load tax summary' });
  }
});

// ═══════════════════════════════════════════════════════════
// TAX FORECAST — real-time Income Tax + NI + VAT for current tax year
// GET /api/tax/forecast
// ═══════════════════════════════════════════════════════════
app.get('/api/tax/forecast', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const now = new Date();

    // Current UK tax year (6 Apr – 5 Apr)
    const taxEndYear = (now.getMonth() < 3 || (now.getMonth() === 3 && now.getDate() < 6))
      ? now.getFullYear() : now.getFullYear() + 1;
    const tyd = taxYearDates(taxEndYear);
    const { startDate, endDate } = tyd;

    // 1. Income & expenses from categorised transactions
    const txRes = await pool.query(`
      SELECT
        COALESCE(SUM(CASE WHEN t.amount > 0 THEN t.amount ELSE 0 END), 0) AS income,
        COALESCE(SUM(CASE WHEN t.amount < 0 THEN ABS(t.amount) ELSE 0 END), 0) AS expenses
      FROM transactions t
      JOIN categories c ON t.category_id = c.id
      WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3
    `, [userId, startDate, endDate]);

    const grossIncome   = parseFloat(txRes.rows[0].income   || 0);
    const grossExpenses = parseFloat(txRes.rows[0].expenses || 0);

    // 2. Mileage deduction (HMRC approved rates)
    let mileageDeduction = 0;
    try {
      const milRes = await pool.query(
        'SELECT COALESCE(SUM(miles), 0) AS total_miles FROM mileage_trips WHERE user_id = $1 AND trip_date >= $2 AND trip_date <= $3',
        [userId, startDate, endDate]
      );
      const totalMiles  = parseFloat(milRes.rows[0].total_miles || 0);
      mileageDeduction  = Math.min(totalMiles, 10000) * 0.45 + Math.max(0, totalMiles - 10000) * 0.25;
    } catch (_) {}

    // 3. Manual allowable expenses
    let manualExpenses = 0;
    try {
      const manRes = await pool.query(
        'SELECT COALESCE(SUM(amount), 0) AS total FROM manual_expenses WHERE user_id = $1 AND expense_date >= $2 AND expense_date <= $3 AND is_allowable = true',
        [userId, startDate, endDate]
      );
      manualExpenses = parseFloat(manRes.rows[0].total || 0);
    } catch (_) {}

    // 4. Net profit YTD
    const netProfitYTD = Math.max(0, grossIncome - grossExpenses - manualExpenses - mileageDeduction);

    // 5. Annualise if ≥2 weeks in and not near year-end
    const taxYearStart     = new Date(startDate + 'T00:00:00');
    const taxYearEnd       = new Date(endDate + 'T23:59:59');
    const totalDays        = Math.ceil((taxYearEnd - taxYearStart) / 86400000);
    const elapsedDays      = Math.min(Math.ceil((now - taxYearStart) / 86400000), totalDays);
    const progressFraction = elapsedDays / totalDays;
    const annualised       = elapsedDays >= 14 && progressFraction < 0.95;
    const projectedProfit  = annualised
      ? Math.round((netProfitYTD / progressFraction) * 100) / 100
      : Math.round(netProfitYTD * 100) / 100;

    // 6. Income Tax + NI
    const taxCalc = calcUKTax(Math.max(0, projectedProfit));

    // 7. VAT liability for current calendar quarter
    let vatLiability = 0;
    let vatQuarterLabel = null;
    try {
      const month = now.getMonth() + 1;
      const q     = Math.ceil(month / 3);
      const yr    = now.getFullYear();
      const quarters = {
        1: { start: `${yr}-01-01`, end: `${yr}-03-31` },
        2: { start: `${yr}-04-01`, end: `${yr}-06-30` },
        3: { start: `${yr}-07-01`, end: `${yr}-09-30` },
        4: { start: `${yr}-10-01`, end: `${yr}-12-31` },
      };
      const { start: vs, end: ve } = quarters[q];
      vatQuarterLabel = `Q${q}-${yr}`;
      const vatRows = await pool.query(`
        SELECT t.amount, c.is_income, COALESCE(t.vat_rate_override, c.vat_rate) AS vat_rate
        FROM transactions t
        JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3 AND COALESCE(t.vat_rate_override, c.vat_rate) IS NOT NULL
      `, [userId, vs, ve]);
      let outputVat = 0, inputVat = 0;
      for (const row of vatRows.rows) {
        const gross      = Math.abs(parseFloat(row.amount));
        const rate       = parseFloat(row.vat_rate);
        const vatAmount  = gross - (gross / (1 + rate / 100));
        if (row.is_income) outputVat += vatAmount; else inputVat += vatAmount;
      }
      vatLiability = Math.max(0, parseFloat((outputVat - inputVat).toFixed(2)));
    } catch (_) {}

    // 8. Combined HMRC total
    const totalHMRC     = taxCalc.totalIncomeTax + taxCalc.totalNI + vatLiability;
    const liabilityRatio = grossIncome > 0 ? totalHMRC / grossIncome : 0;
    const color          = liabilityRatio < 0.15 ? 'green' : liabilityRatio < 0.30 ? 'amber' : 'red';

    res.json({
      success: true,
      tax_year:   tyd.label,
      as_of:      now.toISOString(),
      ytd: {
        gross_income:     grossIncome,
        gross_expenses:   grossExpenses,
        net_profit:       netProfitYTD,
        projected_profit: projectedProfit,
        days_elapsed:     elapsedDays,
        total_days:       totalDays,
        progress_pct:     Math.round(progressFraction * 100),
        annualised,
      },
      breakdown: {
        income_tax: parseFloat(taxCalc.totalIncomeTax.toFixed(2)),
        class2_ni:  0,   // abolished April 2024
        class4_ni:  parseFloat(taxCalc.totalNI.toFixed(2)),
        vat:        vatLiability,
        total:      parseFloat(totalHMRC.toFixed(2)),
      },
      income_tax_detail: {
        personal_allowance:  taxCalc.personalAllowance,
        basic_rate_tax:      parseFloat(taxCalc.basicTax.toFixed(2)),
        higher_rate_tax:     parseFloat(taxCalc.higherTax.toFixed(2)),
        additional_rate_tax: parseFloat(taxCalc.additionalTax.toFixed(2)),
      },
      ni_detail: {
        class4_lower_tax: parseFloat(taxCalc.ni4LowerTax.toFixed(2)),
        class4_upper_tax: parseFloat(taxCalc.ni4UpperTax.toFixed(2)),
      },
      vat_quarter:    vatQuarterLabel,
      color,
      effective_rate: parseFloat(taxCalc.effectiveRate.toFixed(1)),
    });
  } catch (err) {
    console.error('[Tax Forecast]', err);
    res.status(500).json({ success: false, message: 'Failed to calculate tax forecast' });
  }
});

// GET /print/year-end?year=2026
app.get('/print/year-end', authenticateTokenFromQuery, async (req, res) => {
  try {
    const userId = req.user.userId;
    const tyd = taxYearDates(req.query.year || new Date().getFullYear());
    if (!tyd) return res.status(400).send('Invalid year');

    const { startDate, endDate } = tyd;

    const [totalsRes, incomeRes, expenseRes, monthlyRes, userRes] = await Promise.all([
      pool.query(`
        SELECT
          COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) AS income,
          COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) AS expenses,
          COUNT(*) AS tx_count
        FROM transactions WHERE user_id = $1 AND date >= $2 AND date <= $3
      `, [userId, startDate, endDate]),
      pool.query(`
        SELECT c.name, c.icon,
          COALESCE(SUM(t.amount), 0) AS total, COUNT(t.id) AS tx_count
        FROM transactions t JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3 AND t.amount > 0
        GROUP BY c.id, c.name, c.icon ORDER BY total DESC
      `, [userId, startDate, endDate]),
      pool.query(`
        SELECT c.name, c.icon,
          COALESCE(SUM(ABS(t.amount)), 0) AS total, COUNT(t.id) AS tx_count
        FROM transactions t JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3 AND t.amount < 0
        GROUP BY c.id, c.name, c.icon ORDER BY total DESC
      `, [userId, startDate, endDate]),
      pool.query(`
        SELECT TO_CHAR(date, 'YYYY-MM') AS month,
          COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) AS income,
          COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) AS expenses
        FROM transactions WHERE user_id = $1 AND date >= $2 AND date <= $3
        GROUP BY TO_CHAR(date, 'YYYY-MM') ORDER BY month
      `, [userId, startDate, endDate]),
      pool.query('SELECT email, name FROM users WHERE id = $1', [userId]),
    ]);

    let mileageDeduction = 0, mileageMiles = 0;
    try {
      const milRes = await pool.query(`SELECT miles FROM mileage_trips WHERE user_id=$1 AND date>=$2 AND date<=$3 ORDER BY date`, [userId, startDate, endDate]);
      let cum = 0;
      for (const row of milRes.rows) {
        const m = parseFloat(row.miles);
        mileageDeduction += Math.max(0, Math.min(m, Math.max(0, 10000 - cum))) * 0.45 + Math.max(0, m - Math.max(0, 10000 - cum)) * 0.25;
        cum += m; mileageMiles += m;
      }
    } catch (_) {}

    let manualExpensesTotal = 0;
    try {
      const mr = await pool.query(`SELECT COALESCE(SUM(amount),0) AS total FROM manual_expenses WHERE user_id=$1 AND date>=$2 AND date<=$3 AND is_allowable=true`, [userId, startDate, endDate]);
      manualExpensesTotal = parseFloat(mr.rows[0]?.total || 0);
    } catch (_) {}

    const t0 = totalsRes.rows[0];
    const grossIncome = parseFloat(t0.income);
    const grossExpenses = parseFloat(t0.expenses);
    const netProfit = grossIncome - grossExpenses - manualExpensesTotal - mileageDeduction;
    const tax = calcUKTax(Math.max(0, netProfit));
    const user = userRes.rows[0];

    const fmt = n => `£${Number(n).toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    const fmtPct = n => `${Number(n).toFixed(1)}%`;
    const fmtDate2 = d => new Date(d).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });

    const bodyHtml = `
<h1>Year-End Tax Summary — ${tyd.label} Tax Year</h1>
<div class="meta">Tax year 6 April ${tyd.year - 1} – 5 April ${tyd.year} &nbsp;|&nbsp; ${user?.name || user?.email || ''}</div>

<div class="summary-grid">
  <div class="sum-box">
    <div class="sum-label">Total Income</div>
    <div class="sum-val pos">${fmt(grossIncome)}</div>
  </div>
  <div class="sum-box">
    <div class="sum-label">Total Expenses</div>
    <div class="sum-val neg">${fmt(grossExpenses + manualExpensesTotal + mileageDeduction)}</div>
  </div>
  <div class="sum-box" style="border-color:${netProfit>=0?'#d8f3dc':'#fde8e8'};background:${netProfit>=0?'#f0faf2':'#fff5f5'}">
    <div class="sum-label">Net Profit</div>
    <div class="sum-val ${netProfit>=0?'pos':'neg'}">${fmt(netProfit)}</div>
  </div>
  <div class="sum-box" style="border-color:#fef3c7;background:#fffbeb">
    <div class="sum-label">Est. Total Tax</div>
    <div class="sum-val" style="color:#d97706">${fmt(tax.totalTax)}</div>
  </div>
  <div class="sum-box">
    <div class="sum-label">Effective Rate</div>
    <div class="sum-val">${fmtPct(tax.effectiveRate)}</div>
  </div>
  <div class="sum-box">
    <div class="sum-label">Transactions</div>
    <div class="sum-val">${parseInt(t0.tx_count)}</div>
  </div>
</div>

<p class="section-title">Tax Breakdown</p>
<table>
  <thead><tr><th>Component</th><th>Taxable Amount</th><th>Rate</th><th class="num">Tax</th></tr></thead>
  <tbody>
    <tr><td>Personal Allowance</td><td>${fmt(tax.personalAllowance)}</td><td>0%</td><td class="num">£0.00</td></tr>
    <tr><td>Basic Rate Income Tax</td><td>${fmt(tax.basicTaxable)}</td><td>20%</td><td class="num">${fmt(tax.basicTax)}</td></tr>
    ${tax.higherTaxable > 0 ? `<tr><td>Higher Rate Income Tax</td><td>${fmt(tax.higherTaxable)}</td><td>40%</td><td class="num">${fmt(tax.higherTax)}</td></tr>` : ''}
    ${tax.additionalTaxable > 0 ? `<tr><td>Additional Rate Income Tax</td><td>${fmt(tax.additionalTaxable)}</td><td>45%</td><td class="num">${fmt(tax.additionalTax)}</td></tr>` : ''}
    <tr><td>Class 4 NI (lower band)</td><td>${fmt(tax.ni4Lower)}</td><td>6%</td><td class="num">${fmt(tax.ni4LowerTax)}</td></tr>
    ${tax.ni4Upper > 0 ? `<tr><td>Class 4 NI (upper band)</td><td>${fmt(tax.ni4Upper)}</td><td>2%</td><td class="num">${fmt(tax.ni4UpperTax)}</td></tr>` : ''}
    <tr class="total-row highlight"><td colspan="3"><strong>Total Tax Liability</strong></td><td class="num"><strong>${fmt(tax.totalTax)}</strong></td></tr>
    ${tax.poaRequired ? `<tr><td colspan="3">Payment on Account (each × 2)</td><td class="num">${fmt(tax.poaEachPayment)}</td></tr>` : ''}
  </tbody>
</table>

<p class="section-title">Income Sources</p>
<table>
  <thead><tr><th>Category</th><th class="num">Income</th><th class="num">Transactions</th></tr></thead>
  <tbody>
    ${incomeRes.rows.map(r=>`<tr><td>${r.icon||''} ${r.name}</td><td class="num pos">${fmt(r.total)}</td><td class="num">${r.tx_count}</td></tr>`).join('')}
    ${incomeRes.rows.length===0 ? '<tr><td colspan="3" style="color:#9ca3af;text-align:center">No income recorded</td></tr>' : ''}
    <tr class="total-row"><td>Total Income</td><td class="num pos">${fmt(grossIncome)}</td><td></td></tr>
  </tbody>
</table>

<p class="section-title">Expense Breakdown</p>
<table>
  <thead><tr><th>Category</th><th class="num">Amount</th><th class="num">Transactions</th></tr></thead>
  <tbody>
    ${expenseRes.rows.map(r=>`<tr><td>${r.icon||''} ${r.name}</td><td class="num neg">${fmt(r.total)}</td><td class="num">${r.tx_count}</td></tr>`).join('')}
    ${mileageMiles > 0 ? `<tr><td>🚗 HMRC Mileage (${mileageMiles.toFixed(0)} miles)</td><td class="num neg">${fmt(mileageDeduction)}</td><td class="num">—</td></tr>` : ''}
    ${manualExpensesTotal > 0 ? `<tr><td>📝 Manual Allowable Expenses</td><td class="num neg">${fmt(manualExpensesTotal)}</td><td class="num">—</td></tr>` : ''}
    <tr class="total-row"><td>Total Deductions</td><td class="num neg">${fmt(grossExpenses + mileageDeduction + manualExpensesTotal)}</td><td></td></tr>
  </tbody>
</table>

<p class="section-title">Monthly Performance</p>
<table>
  <thead><tr><th>Month</th><th class="num">Income</th><th class="num">Expenses</th><th class="num">Net</th></tr></thead>
  <tbody>
    ${monthlyRes.rows.map(r=>{const mn=parseFloat(r.income)-parseFloat(r.expenses);return`<tr><td>${r.month}</td><td class="num pos">${fmt(r.income)}</td><td class="num neg">${fmt(r.expenses)}</td><td class="num ${mn>=0?'pos':'neg'}">${fmt(mn)}</td></tr>`;}).join('')}
    ${monthlyRes.rows.length===0 ? '<tr><td colspan="4" style="color:#9ca3af;text-align:center">No data</td></tr>' : ''}
  </tbody>
</table>

<p class="section-title">Key Dates — ${tyd.label} Tax Year</p>
<table>
  <thead><tr><th>Deadline</th><th>Date</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td>Tax year end</td><td>${fmtDate2(endDate)}</td><td>Last day of ${tyd.label} tax year</td></tr>
    <tr><td>Online SA filing deadline</td><td>${fmtDate2(`${tyd.year + 1}-01-31`)}</td><td>Self-Assessment return due to HMRC</td></tr>
    <tr><td>Balancing payment</td><td>${fmtDate2(`${tyd.year + 1}-01-31`)}</td><td>Pay any remaining tax owed</td></tr>
    ${tax.poaRequired ? `
    <tr><td>1st Payment on Account</td><td>${fmtDate2(`${tyd.year + 1}-01-31`)}</td><td>${fmt(tax.poaEachPayment)} (50% of tax bill)</td></tr>
    <tr><td>2nd Payment on Account</td><td>${fmtDate2(`${tyd.year + 1}-07-31`)}</td><td>${fmt(tax.poaEachPayment)} (50% of tax bill)</td></tr>
    ` : ''}
  </tbody>
</table>
<p style="font-size:0.78rem;color:#9ca3af;margin-top:0.5rem">⚠️ Figures are estimates based on your FinOwl data. Consult a qualified accountant before filing.</p>
    `;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.send(printLayout(`Year-End Tax Summary ${tyd.label}`, bodyHtml));
  } catch (err) {
    console.error('Print year-end error:', err);
    res.status(500).send('Print failed');
  }
});

// ═══════════════════════════════════════════════════════════
// INVOICES — CRUD + REMINDERS
// ═══════════════════════════════════════════════════════════

// ─── Helper: next invoice number ─────────────────────────
async function nextInvoiceNumber(userId) {
  const res = await pool.query(
    `SELECT invoice_number FROM invoices WHERE user_id = $1 ORDER BY id DESC LIMIT 1`,
    [userId]
  );
  if (!res.rows[0]) return 'INV-001';
  const last = res.rows[0].invoice_number;
  const match = last.match(/(\d+)$/);
  const next = match ? parseInt(match[1]) + 1 : 1;
  return `INV-${String(next).padStart(3, '0')}`;
}

// ─── GET /api/invoices ────────────────────────────────────
app.get('/api/invoices', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { status } = req.query;

    let where = 'WHERE i.user_id = $1';
    const params = [userId];
    if (status && status !== 'all') {
      params.push(status);
      where += ` AND i.status = $${params.length}`;
    }

    // Auto-set overdue status for unpaid past-due invoices
    await pool.query(`
      UPDATE invoices
         SET status = 'overdue'
       WHERE user_id = $1
         AND status = 'sent'
         AND due_date < CURRENT_DATE
    `, [userId]);

    const result = await pool.query(`
      SELECT i.*,
             (SELECT COUNT(*) FROM invoice_items ii WHERE ii.invoice_id = i.id) AS item_count,
             (SELECT COUNT(*) FROM invoice_reminder_log rl WHERE rl.invoice_id = i.id) AS reminders_sent
        FROM invoices i
       ${where}
       ORDER BY i.created_at DESC
    `, params);

    // Stats
    const statsRes = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE status != 'draft')             AS total,
        COALESCE(SUM(total) FILTER (WHERE status IN ('sent','overdue')), 0) AS outstanding,
        COALESCE(SUM(total) FILTER (WHERE status = 'paid'),   0) AS paid_total,
        COUNT(*) FILTER (WHERE status = 'overdue')            AS overdue_count,
        COUNT(*) FILTER (WHERE status = 'draft')              AS draft_count
      FROM invoices WHERE user_id = $1
    `, [userId]);

    res.json({ success: true, invoices: result.rows, stats: statsRes.rows[0] });
  } catch (err) {
    console.error('GET /api/invoices error:', err);
    res.status(500).json({ error: 'Failed to load invoices' });
  }
});

// ─── POST /api/invoices ───────────────────────────────────
app.post('/api/invoices', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const {
      client_name, client_email, client_address,
      issue_date, due_date, notes, vat_rate,
      items = [],
      auto_reminders_enabled = true,
    } = req.body;

    if (!client_name) return res.status(400).json({ error: 'client_name required' });

    const invNum = await nextInvoiceNumber(userId);

    // Calculate totals
    let subtotal = 0;
    for (const item of items) subtotal += parseFloat(item.quantity || 1) * parseFloat(item.unit_price || 0);
    const vatRateNum = parseFloat(vat_rate || 0);
    const vatAmount  = parseFloat((subtotal * vatRateNum / 100).toFixed(2));
    const total      = parseFloat((subtotal + vatAmount).toFixed(2));

    const inv = await pool.query(`
      INSERT INTO invoices
        (user_id, invoice_number, client_name, client_email, client_address,
         issue_date, due_date, notes, vat_rate, subtotal, vat_amount, total,
         status, auto_reminders_enabled)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'draft',$13)
      RETURNING *
    `, [userId, invNum, client_name, client_email || null, client_address || null,
        issue_date || new Date().toISOString().slice(0,10),
        due_date || null, notes || null, vatRateNum,
        subtotal.toFixed(2), vatAmount, total, auto_reminders_enabled]);

    const invoice = inv.rows[0];

    // Insert line items
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      const qty = parseFloat(item.quantity || 1);
      const price = parseFloat(item.unit_price || 0);
      const amount = parseFloat((qty * price).toFixed(2));
      await pool.query(`
        INSERT INTO invoice_items (invoice_id, description, quantity, unit_price, amount, sort_order)
        VALUES ($1,$2,$3,$4,$5,$6)
      `, [invoice.id, item.description, qty, price, amount, i]);
    }

    logAuditEvent({
      userId,
      eventType: 'invoice_created',
      entityType: 'invoice',
      entityId: invoice.id,
      details: { invoice_number: invoice.invoice_number, client_name, total: invoice.total, status: invoice.status },
      req,
    });

    res.status(201).json({ success: true, invoice });
  } catch (err) {
    console.error('POST /api/invoices error:', err);
    res.status(500).json({ error: 'Failed to create invoice' });
  }
});

// ─── GET /api/invoices/stats — Overview stats ─────────────
app.get('/api/invoices/stats', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Auto-set overdue
    await pool.query(
      `UPDATE invoices SET status = 'overdue' WHERE user_id = $1 AND status = 'sent' AND due_date < CURRENT_DATE`,
      [userId]
    );

    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0,0,0,0);

    const r = await pool.query(`
      SELECT
        COALESCE(SUM(total) FILTER (WHERE status IN ('sent','overdue')), 0) AS outstanding,
        COUNT(*)            FILTER (WHERE status = 'overdue')               AS overdue_count,
        COALESCE(SUM(total) FILTER (WHERE status = 'paid' AND paid_at >= $2), 0) AS paid_this_month
      FROM invoices WHERE user_id = $1
    `, [userId, startOfMonth.toISOString()]);

    res.json({ success: true, stats: r.rows[0] });
  } catch (err) {
    console.error('GET /api/invoices/stats error:', err);
    res.status(500).json({ error: 'Failed to load stats' });
  }
});

// ─── GET /api/invoices/:id ────────────────────────────────
app.get('/api/invoices/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { id } = req.params;

    const inv = await pool.query(
      `SELECT * FROM invoices WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );
    if (!inv.rows[0]) return res.status(404).json({ error: 'Not found' });

    const items = await pool.query(
      `SELECT * FROM invoice_items WHERE invoice_id = $1 ORDER BY sort_order, id`,
      [id]
    );
    const reminders = await pool.query(
      `SELECT * FROM invoice_reminder_log WHERE invoice_id = $1 ORDER BY reminder_day`,
      [id]
    );

    res.json({
      success: true,
      invoice: inv.rows[0],
      items: items.rows,
      reminders: reminders.rows,
    });
  } catch (err) {
    console.error('GET /api/invoices/:id error:', err);
    res.status(500).json({ error: 'Failed to load invoice' });
  }
});

// ─── PUT /api/invoices/:id ────────────────────────────────
app.put('/api/invoices/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { id } = req.params;

    const existing = await pool.query(
      `SELECT * FROM invoices WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );
    if (!existing.rows[0]) return res.status(404).json({ error: 'Not found' });
    if (existing.rows[0].status === 'paid') {
      return res.status(400).json({ error: 'Cannot edit a paid invoice' });
    }

    const {
      client_name, client_email, client_address,
      issue_date, due_date, notes, vat_rate, items = [],
      auto_reminders_enabled,
    } = req.body;

    // Recalculate totals
    let subtotal = 0;
    for (const item of items) subtotal += parseFloat(item.quantity || 1) * parseFloat(item.unit_price || 0);
    const vatRateNum = parseFloat(vat_rate ?? existing.rows[0].vat_rate ?? 0);
    const vatAmount  = parseFloat((subtotal * vatRateNum / 100).toFixed(2));
    const total      = parseFloat((subtotal + vatAmount).toFixed(2));

    const updated = await pool.query(`
      UPDATE invoices SET
        client_name  = COALESCE($3, client_name),
        client_email = COALESCE($4, client_email),
        client_address = COALESCE($5, client_address),
        issue_date   = COALESCE($6, issue_date),
        due_date     = COALESCE($7, due_date),
        notes        = COALESCE($8, notes),
        vat_rate     = $9,
        subtotal     = $10,
        vat_amount   = $11,
        total        = $12,
        auto_reminders_enabled = COALESCE($13, auto_reminders_enabled),
        updated_at   = NOW()
      WHERE id = $1 AND user_id = $2
      RETURNING *
    `, [id, userId, client_name, client_email, client_address,
        issue_date, due_date, notes, vatRateNum,
        subtotal.toFixed(2), vatAmount, total,
        auto_reminders_enabled ?? null]);

    // Replace line items
    await pool.query(`DELETE FROM invoice_items WHERE invoice_id = $1`, [id]);
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      const qty = parseFloat(item.quantity || 1);
      const price = parseFloat(item.unit_price || 0);
      const amount = parseFloat((qty * price).toFixed(2));
      await pool.query(`
        INSERT INTO invoice_items (invoice_id, description, quantity, unit_price, amount, sort_order)
        VALUES ($1,$2,$3,$4,$5,$6)
      `, [id, item.description, qty, price, amount, i]);
    }

    res.json({ success: true, invoice: updated.rows[0] });
  } catch (err) {
    console.error('PUT /api/invoices/:id error:', err);
    res.status(500).json({ error: 'Failed to update invoice' });
  }
});

// ─── DELETE /api/invoices/:id ─────────────────────────────
app.delete('/api/invoices/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { id } = req.params;

    const existing = await pool.query(
      `SELECT * FROM invoices WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );
    if (!existing.rows[0]) return res.status(404).json({ error: 'Not found' });

    await pool.query(`DELETE FROM invoices WHERE id = $1 AND user_id = $2`, [id, userId]);
    logAuditEvent({
      userId,
      eventType: 'invoice_deleted',
      entityType: 'invoice',
      entityId: parseInt(id),
      details: { invoice_number: existing.rows[0].invoice_number, client_name: existing.rows[0].client_name, total: existing.rows[0].total },
      req,
    });
    res.json({ success: true });
  } catch (err) {
    console.error('DELETE /api/invoices/:id error:', err);
    res.status(500).json({ error: 'Failed to delete invoice' });
  }
});

// ─── POST /api/invoices/:id/send ──────────────────────────
app.post('/api/invoices/:id/send', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { id } = req.params;

    const inv = await pool.query(
      `SELECT * FROM invoices WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );
    if (!inv.rows[0]) return res.status(404).json({ error: 'Not found' });
    if (inv.rows[0].status === 'paid') return res.status(400).json({ error: 'Invoice already paid' });

    const viewToken = crypto.randomBytes(32).toString('hex');
    const updated = await pool.query(`
      UPDATE invoices SET status = 'sent', sent_at = NOW(), view_token = $3, updated_at = NOW()
      WHERE id = $1 AND user_id = $2
      RETURNING *
    `, [id, userId, viewToken]);

    res.json({ success: true, invoice: updated.rows[0], viewLink: `${req.protocol}://${req.get('host')}/i/${viewToken}` });
  } catch (err) {
    console.error('POST /api/invoices/:id/send error:', err);
    res.status(500).json({ error: 'Failed to mark invoice as sent' });
  }
});

// ─── POST /api/invoices/:id/paid ──────────────────────────
app.post('/api/invoices/:id/paid', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { id } = req.params;
    const { paid_at, matched_transaction_id } = req.body;

    const inv = await pool.query(
      `SELECT * FROM invoices WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );
    if (!inv.rows[0]) return res.status(404).json({ error: 'Not found' });

    const updated = await pool.query(`
      UPDATE invoices SET
        status = 'paid',
        paid_at = COALESCE($3, NOW()),
        matched_transaction_id = $4,
        updated_at = NOW()
      WHERE id = $1 AND user_id = $2
      RETURNING *
    `, [id, userId, paid_at || null, matched_transaction_id || null]);

    res.json({ success: true, invoice: updated.rows[0] });
  } catch (err) {
    console.error('POST /api/invoices/:id/paid error:', err);
    res.status(500).json({ error: 'Failed to mark invoice as paid' });
  }
});

// ─── PATCH /api/invoices/:id/reminders ───────────────────
app.patch('/api/invoices/:id/reminders', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { id } = req.params;
    const { auto_reminders_enabled } = req.body;

    const updated = await pool.query(`
      UPDATE invoices SET auto_reminders_enabled = $3, updated_at = NOW()
      WHERE id = $1 AND user_id = $2
      RETURNING *
    `, [id, userId, auto_reminders_enabled]);

    if (!updated.rows[0]) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true, invoice: updated.rows[0] });
  } catch (err) {
    console.error('PATCH /api/invoices/:id/reminders error:', err);
    res.status(500).json({ error: 'Failed to update reminders' });
  }
});

// ─── BUSINESS PROFILE HELPERS ────────────────────────────
async function getBusinessProfile(userId) {
  const r = await pool.query(
    `SELECT * FROM business_profiles WHERE user_id = $1`,
    [userId]
  );
  return r.rows[0] || null;
}

// ─── PDF GENERATION HELPER ────────────────────────────────
function generateInvoicePDF(invoice, items, profile) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    const chunks = [];
    doc.on('data', chunk => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const fmtGBP = (n) => `£${parseFloat(n || 0).toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    const fmtDate = (d) => d ? new Date(d).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }) : '—';

    const amber = '#D4920B';
    const ink = '#0A0F1A';
    const muted = '#6B7280';
    const pageW = doc.page.width - 100; // usable width (50 margin each side)

    // ── Header bar ──────────────────────────────────────────
    doc.rect(50, 50, pageW, 70).fillColor(ink).fill();

    // Business name or FinOwl
    const bizName = (profile && profile.business_name) ? profile.business_name : 'FinOwl';
    doc.fillColor('#FFFFFF').fontSize(18).font('Helvetica-Bold')
       .text(bizName, 65, 68, { lineBreak: false });

    // Invoice number (right side)
    doc.fillColor(amber).fontSize(12).font('Helvetica-Bold')
       .text(invoice.invoice_number, 65, 95, { width: pageW - 30, align: 'right' });

    doc.fillColor(ink);

    // ── From / To block ──────────────────────────────────────
    let y = 145;

    // From column
    doc.fontSize(8).font('Helvetica-Bold').fillColor(muted)
       .text('FROM', 50, y, { width: 230 });
    y += 14;
    if (profile && profile.business_name) {
      doc.fontSize(11).font('Helvetica-Bold').fillColor(ink)
         .text(profile.business_name, 50, y, { width: 230 });
      y += 15;
    }
    if (profile && profile.business_address) {
      doc.fontSize(9).font('Helvetica').fillColor(muted)
         .text(profile.business_address, 50, y, { width: 230, lineBreak: true });
      y = doc.y + 4;
    }
    if (profile && profile.business_email) {
      doc.fontSize(9).font('Helvetica').fillColor(muted)
         .text(profile.business_email, 50, y, { width: 230 });
      y += 14;
    }
    if (profile && profile.business_phone) {
      doc.fontSize(9).font('Helvetica').fillColor(muted)
         .text(profile.business_phone, 50, y, { width: 230 });
      y += 14;
    }

    // To column (right side)
    let toY = 145;
    doc.fontSize(8).font('Helvetica-Bold').fillColor(muted)
       .text('BILL TO', 310, toY, { width: 230 });
    toY += 14;
    doc.fontSize(11).font('Helvetica-Bold').fillColor(ink)
       .text(invoice.client_name, 310, toY, { width: 230 });
    toY += 15;
    if (invoice.client_address) {
      doc.fontSize(9).font('Helvetica').fillColor(muted)
         .text(invoice.client_address, 310, toY, { width: 230, lineBreak: true });
      toY = doc.y + 4;
    }
    if (invoice.client_email) {
      doc.fontSize(9).font('Helvetica').fillColor(muted)
         .text(invoice.client_email, 310, toY, { width: 230 });
      toY += 14;
    }

    // ── Invoice meta row ──────────────────────────────────────
    y = Math.max(y, toY) + 20;

    doc.moveTo(50, y).lineTo(50 + pageW, y).strokeColor('#E5E2DB').lineWidth(1).stroke();
    y += 12;

    const metaItems = [
      ['Invoice No.', invoice.invoice_number],
      ['Issue Date', fmtDate(invoice.issue_date)],
      ['Due Date', invoice.due_date ? fmtDate(invoice.due_date) : '—'],
    ];
    const metaColW = pageW / metaItems.length;
    metaItems.forEach(([label, value], i) => {
      doc.fontSize(8).font('Helvetica-Bold').fillColor(muted)
         .text(label, 50 + i * metaColW, y, { width: metaColW - 10 });
      doc.fontSize(10).font('Helvetica-Bold').fillColor(ink)
         .text(value, 50 + i * metaColW, y + 14, { width: metaColW - 10 });
    });
    y += 40;

    doc.moveTo(50, y).lineTo(50 + pageW, y).strokeColor('#E5E2DB').lineWidth(1).stroke();
    y += 16;

    // ── Line items table ─────────────────────────────────────
    const col = { desc: 50, qty: 340, price: 400, amount: 470 };

    // Table header
    doc.rect(50, y, pageW, 22).fillColor('#F5F4F1').fill();
    doc.fillColor(muted).fontSize(8).font('Helvetica-Bold');
    doc.text('DESCRIPTION', col.desc + 8, y + 7);
    doc.text('QTY', col.qty, y + 7, { width: 50, align: 'center' });
    doc.text('UNIT PRICE', col.price, y + 7, { width: 60, align: 'right' });
    doc.text('AMOUNT', col.amount, y + 7, { width: 80, align: 'right' });
    y += 30;

    // Table rows
    items.forEach((item, idx) => {
      if (y > 700) { doc.addPage(); y = 50; }
      if (idx % 2 === 0) {
        doc.rect(50, y - 4, pageW, 22).fillColor('#FAFAF8').fill();
      }
      doc.fillColor(ink).fontSize(9).font('Helvetica');
      doc.text(item.description, col.desc + 8, y, { width: 270 });
      doc.text(String(parseFloat(item.quantity)), col.qty, y, { width: 50, align: 'center' });
      doc.text(fmtGBP(item.unit_price), col.price, y, { width: 60, align: 'right' });
      doc.fillColor(ink).font('Helvetica-Bold');
      doc.text(fmtGBP(item.amount), col.amount, y, { width: 80, align: 'right' });
      y += 22;
    });

    y += 8;
    doc.moveTo(50, y).lineTo(50 + pageW, y).strokeColor('#E5E2DB').lineWidth(1).stroke();
    y += 12;

    // ── Totals ──────────────────────────────────────────────
    const totalsX = 360;
    const totalsLabelW = 100;
    const totalsValueW = 80;
    const totalsValueX = totalsX + totalsLabelW;

    if (parseFloat(invoice.vat_rate) > 0) {
      doc.fontSize(9).font('Helvetica').fillColor(muted)
         .text('Subtotal', totalsX, y, { width: totalsLabelW });
      doc.fontSize(9).font('Helvetica').fillColor(ink)
         .text(fmtGBP(invoice.subtotal), totalsValueX, y, { width: totalsValueW, align: 'right' });
      y += 16;

      doc.fontSize(9).font('Helvetica').fillColor(muted)
         .text(`VAT (${invoice.vat_rate}%)`, totalsX, y, { width: totalsLabelW });
      doc.fontSize(9).font('Helvetica').fillColor(ink)
         .text(fmtGBP(invoice.vat_amount), totalsValueX, y, { width: totalsValueW, align: 'right' });
      y += 16;
    }

    // Total row with amber background
    doc.rect(totalsX - 10, y - 4, totalsLabelW + totalsValueW + 20, 26).fillColor(amber).fill();
    doc.fontSize(11).font('Helvetica-Bold').fillColor('#FFFFFF')
       .text('TOTAL DUE', totalsX, y + 2, { width: totalsLabelW });
    doc.fontSize(11).font('Helvetica-Bold').fillColor('#FFFFFF')
       .text(fmtGBP(invoice.total), totalsValueX, y + 2, { width: totalsValueW, align: 'right' });
    y += 40;

    // ── Payment Details ──────────────────────────────────────
    const hasBankDetails = profile && (profile.bank_sort_code || profile.bank_account_number || profile.bank_name);
    if (hasBankDetails) {
      if (y > 650) { doc.addPage(); y = 50; }
      doc.rect(50, y, pageW, 14).fillColor('#F5F4F1').fill();
      doc.fontSize(9).font('Helvetica-Bold').fillColor(muted)
         .text('PAYMENT DETAILS', 58, y + 3);
      y += 22;

      if (profile.bank_name) {
        doc.fontSize(9).font('Helvetica').fillColor(muted)
           .text('Bank:', 50, y, { lineBreak: false });
        doc.fillColor(ink).text('  ' + profile.bank_name, { lineBreak: false });
        y += 14;
      }
      if (profile.bank_sort_code) {
        doc.fontSize(9).font('Helvetica').fillColor(muted)
           .text('Sort Code:', 50, y, { lineBreak: false });
        doc.fillColor(ink).text('  ' + profile.bank_sort_code, { lineBreak: false });
        y += 14;
      }
      if (profile.bank_account_number) {
        doc.fontSize(9).font('Helvetica').fillColor(muted)
           .text('Account Number:', 50, y, { lineBreak: false });
        doc.fillColor(ink).text('  ' + profile.bank_account_number, { lineBreak: false });
        y += 14;
      }
      if (profile.bank_reference) {
        doc.fontSize(9).font('Helvetica').fillColor(muted)
           .text('Reference:', 50, y, { lineBreak: false });
        doc.fillColor(ink).text('  ' + profile.bank_reference, { lineBreak: false });
        y += 14;
      }
      y += 10;
    }

    // ── Notes / Terms ───────────────────────────────────────
    const terms = (profile && profile.payment_terms) ? profile.payment_terms : null;
    const notes = invoice.notes;
    if (terms || notes) {
      if (y > 680) { doc.addPage(); y = 50; }
      doc.rect(50, y, pageW, 14).fillColor('#F5F4F1').fill();
      doc.fontSize(9).font('Helvetica-Bold').fillColor(muted)
         .text('NOTES & TERMS', 58, y + 3);
      y += 22;
      if (terms) {
        doc.fontSize(9).font('Helvetica').fillColor(muted)
           .text(terms, 50, y, { width: pageW });
        y = doc.y + 8;
      }
      if (notes) {
        doc.fontSize(9).font('Helvetica').fillColor(ink)
           .text(notes, 50, y, { width: pageW });
        y = doc.y + 8;
      }
    }

    // ── Footer ──────────────────────────────────────────────
    doc.moveTo(50, 780).lineTo(50 + pageW, 780).strokeColor('#E5E2DB').lineWidth(1).stroke();
    doc.fontSize(8).font('Helvetica').fillColor(muted)
       .text('Generated by FinOwl — smart accounting for UK sole traders  |  finowl.co.uk', 50, 788, { width: pageW, align: 'center' });

    doc.end();
  });
}

// ─── GET /api/settings/profile ───────────────────────────
app.get('/api/settings/profile', authenticateToken, async (req, res) => {
  try {
    const profile = await getBusinessProfile(req.user.userId);
    res.json({ success: true, profile: profile || {} });
  } catch (err) {
    console.error('GET /api/settings/profile error:', err);
    res.status(500).json({ error: 'Failed to load profile' });
  }
});

// ─── POST /api/settings/profile ──────────────────────────
app.post('/api/settings/profile', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const {
      business_name, business_address, business_phone, business_email,
      bank_name, bank_sort_code, bank_account_number, bank_reference,
      payment_terms, invoice_notes,
    } = req.body;

    await pool.query(`
      INSERT INTO business_profiles
        (user_id, business_name, business_address, business_phone, business_email,
         bank_name, bank_sort_code, bank_account_number, bank_reference,
         payment_terms, invoice_notes, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
      ON CONFLICT (user_id) DO UPDATE SET
        business_name       = EXCLUDED.business_name,
        business_address    = EXCLUDED.business_address,
        business_phone      = EXCLUDED.business_phone,
        business_email      = EXCLUDED.business_email,
        bank_name           = EXCLUDED.bank_name,
        bank_sort_code      = EXCLUDED.bank_sort_code,
        bank_account_number = EXCLUDED.bank_account_number,
        bank_reference      = EXCLUDED.bank_reference,
        payment_terms       = EXCLUDED.payment_terms,
        invoice_notes       = EXCLUDED.invoice_notes,
        updated_at          = NOW()
    `, [userId, business_name||null, business_address||null, business_phone||null,
        business_email||null, bank_name||null, bank_sort_code||null,
        bank_account_number||null, bank_reference||null,
        payment_terms||null, invoice_notes||null]);

    res.json({ success: true });
  } catch (err) {
    console.error('POST /api/settings/profile error:', err);
    res.status(500).json({ error: 'Failed to save profile' });
  }
});

// ─── GET /api/invoices/:id/pdf ────────────────────────────
app.get('/api/invoices/:id/pdf', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { id } = req.params;

    const invRes = await pool.query(
      `SELECT * FROM invoices WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );
    if (!invRes.rows[0]) return res.status(404).json({ error: 'Not found' });

    const invoice = invRes.rows[0];
    const itemsRes = await pool.query(
      `SELECT * FROM invoice_items WHERE invoice_id = $1 ORDER BY sort_order, id`,
      [invoice.id]
    );
    const profile = await getBusinessProfile(userId);
    const pdfBuffer = await generateInvoicePDF(invoice, itemsRes.rows, profile);

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${invoice.invoice_number}.pdf"`);
    res.send(pdfBuffer);
  } catch (err) {
    console.error('GET /api/invoices/:id/pdf error:', err);
    res.status(500).json({ error: 'Failed to generate PDF' });
  }
});

// ─── GET /api/invoices/p/:token/pdf — Public PDF download ─
app.get('/api/invoices/p/:token/pdf', async (req, res) => {
  try {
    const { token } = req.params;
    const invRes = await pool.query(
      `SELECT i.*, u.id AS owner_id FROM invoices i
         JOIN users u ON i.user_id = u.id
        WHERE i.view_token = $1`,
      [token]
    );
    if (!invRes.rows[0]) return res.status(404).send('Invoice not found');

    const invoice = invRes.rows[0];
    const itemsRes = await pool.query(
      `SELECT * FROM invoice_items WHERE invoice_id = $1 ORDER BY sort_order, id`,
      [invoice.id]
    );
    const profile = await getBusinessProfile(invoice.owner_id);
    const pdfBuffer = await generateInvoicePDF(invoice, itemsRes.rows, profile);

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${invoice.invoice_number}.pdf"`);
    res.send(pdfBuffer);
  } catch (err) {
    console.error('GET /api/invoices/p/:token/pdf error:', err);
    res.status(500).send('Error generating PDF');
  }
});

// ─── POST /api/invoices/:id/email ─────────────────────────
app.post('/api/invoices/:id/email', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { id } = req.params;

    const invRes = await pool.query(
      `SELECT * FROM invoices WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );
    if (!invRes.rows[0]) return res.status(404).json({ error: 'Not found' });
    const invoice = invRes.rows[0];

    if (!invoice.client_email) {
      return res.status(400).json({ error: 'Invoice has no client email address' });
    }

    const profile = await getBusinessProfile(userId);
    const bizName = (profile && profile.business_name) ? profile.business_name : 'Your service provider';

    // Ensure invoice is sent (has view token)
    let viewToken = invoice.view_token;
    if (!viewToken) {
      viewToken = crypto.randomBytes(32).toString('hex');
      await pool.query(
        `UPDATE invoices SET status = 'sent', sent_at = NOW(), view_token = $3, updated_at = NOW()
         WHERE id = $1 AND user_id = $2`,
        [id, userId, viewToken]
      );
    } else if (invoice.status === 'draft') {
      await pool.query(
        `UPDATE invoices SET status = 'sent', sent_at = COALESCE(sent_at, NOW()), updated_at = NOW()
         WHERE id = $1 AND user_id = $2`,
        [id, userId]
      );
    }

    const baseUrl = process.env.APP_URL || 'https://finowl.co.uk';
    const viewLink = `${baseUrl}/i/${viewToken}`;
    const pdfLink  = `${baseUrl}/api/invoices/p/${viewToken}/pdf`;

    const fmtGBP = (n) => `£${parseFloat(n || 0).toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    const fmtDate = (d) => d ? new Date(d).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }) : '—';

    const htmlBody = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { background:#f5f4f1; font-family:'Helvetica Neue',Arial,sans-serif; color:#0a0f1a; }
    .wrap { max-width:580px; margin:32px auto; }
    .header { background:#0a0f1a; border-radius:12px 12px 0 0; padding:20px 28px; display:flex; align-items:center; gap:10px; }
    .header-owl { background:#d4920b; border-radius:50%; width:34px; height:34px; display:inline-flex; align-items:center; justify-content:center; font-size:16px; }
    .header-name { color:#fff; font-size:18px; font-weight:700; letter-spacing:-0.3px; }
    .body { background:#fff; padding:28px; border-radius:0 0 12px 12px; border:1px solid #e5e2db; border-top:none; }
    h2 { font-size:20px; font-weight:700; margin-bottom:6px; }
    p.sub { color:#6b7280; font-size:14px; margin-bottom:20px; line-height:1.6; }
    .inv-box { background:#f9f8f6; border:1px solid #e5e2db; border-radius:10px; padding:18px 20px; margin:20px 0; }
    .inv-row { display:flex; justify-content:space-between; padding:7px 0; font-size:14px; border-bottom:1px solid #f0eee9; }
    .inv-row:last-child { border-bottom:none; }
    .inv-label { color:#6b7280; }
    .inv-total { font-size:16px; font-weight:700; color:#0a0f1a; padding-top:10px; }
    .btn { display:inline-block; background:#d4920b; color:#fff; text-decoration:none; padding:13px 26px; border-radius:8px; font-weight:600; font-size:14px; margin-top:16px; margin-right:10px; }
    .btn-outline { background:#fff; color:#0a0f1a; border:1.5px solid #e5e2db; }
    .divider { height:1px; background:#e5e2db; margin:20px 0; }
    .footer { margin-top:20px; text-align:center; font-size:12px; color:#9ca3af; }
    .footer a { color:#d4920b; text-decoration:none; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <span class="header-owl">🦉</span>
      <span class="header-name">${bizName}</span>
    </div>
    <div class="body">
      <h2>Invoice ${invoice.invoice_number}</h2>
      <p class="sub">Please find your invoice details below. Payment is due by ${fmtDate(invoice.due_date)}.</p>

      <div class="inv-box">
        <div class="inv-row"><span class="inv-label">Invoice No.</span><span>${invoice.invoice_number}</span></div>
        <div class="inv-row"><span class="inv-label">Issue Date</span><span>${fmtDate(invoice.issue_date)}</span></div>
        <div class="inv-row"><span class="inv-label">Due Date</span><span>${fmtDate(invoice.due_date)}</span></div>
        ${parseFloat(invoice.vat_rate) > 0 ? `
        <div class="inv-row"><span class="inv-label">Subtotal</span><span>${fmtGBP(invoice.subtotal)}</span></div>
        <div class="inv-row"><span class="inv-label">VAT (${invoice.vat_rate}%)</span><span>${fmtGBP(invoice.vat_amount)}</span></div>` : ''}
        <div class="inv-row inv-total"><span>Total Due</span><span>${fmtGBP(invoice.total)}</span></div>
      </div>

      ${profile && profile.bank_sort_code ? `
      <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:14px 16px;margin:16px 0;font-size:14px">
        <div style="font-weight:600;color:#166534;margin-bottom:8px">💳 Payment Details</div>
        ${profile.bank_name ? `<div style="display:flex;gap:8px;margin-bottom:4px"><span style="color:#6b7280;min-width:120px">Bank</span><span>${profile.bank_name}</span></div>` : ''}
        ${profile.bank_sort_code ? `<div style="display:flex;gap:8px;margin-bottom:4px"><span style="color:#6b7280;min-width:120px">Sort Code</span><span>${profile.bank_sort_code}</span></div>` : ''}
        ${profile.bank_account_number ? `<div style="display:flex;gap:8px;margin-bottom:4px"><span style="color:#6b7280;min-width:120px">Account No.</span><span>${profile.bank_account_number}</span></div>` : ''}
        ${profile.bank_reference ? `<div style="display:flex;gap:8px"><span style="color:#6b7280;min-width:120px">Reference</span><span>${profile.bank_reference || invoice.invoice_number}</span></div>` : ''}
      </div>` : ''}

      ${invoice.notes ? `<div style="background:#fff8e6;border:1px solid #f5dfa3;border-radius:8px;padding:14px 16px;margin:16px 0;font-size:14px;color:#6b7280">${invoice.notes}</div>` : ''}

      <div style="margin-top:20px">
        <a href="${viewLink}" class="btn">View Invoice Online</a>
        <a href="${pdfLink}" class="btn btn-outline">⬇ Download PDF</a>
      </div>

      <div class="divider"></div>
      <div class="footer">
        <p>Sent by <a href="https://finowl.co.uk">FinOwl</a> on behalf of ${bizName}</p>
      </div>
    </div>
  </div>
</body>
</html>`;

    // Send email via email.js utility
    const emailResult = await sendInvoiceEmail({
      to: invoice.client_email,
      subject: `Invoice ${invoice.invoice_number} from ${bizName} — ${fmtGBP(invoice.total)} due ${fmtDate(invoice.due_date)}`,
      htmlBody,
    });
    if (!emailResult.ok && !emailResult.skipped) {
      return res.status(502).json({ error: `Email send failed: ${emailResult.error}` });
    }

    // Reload the updated invoice
    const updated = await pool.query(`SELECT * FROM invoices WHERE id = $1`, [id]);
    res.json({ success: true, invoice: updated.rows[0], viewLink, pdfLink });
  } catch (err) {
    console.error('POST /api/invoices/:id/email error:', err);
    res.status(500).json({ error: 'Failed to send invoice email' });
  }
});

// ─── GET /api/notification-settings ──────────────────────
app.get('/api/notification-settings', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const result = await pool.query(
      `SELECT * FROM notification_settings WHERE user_id = $1`,
      [userId]
    );
    if (!result.rows[0]) {
      // Return defaults
      return res.json({
        success: true,
        settings: {
          vat_deadline_reminders: true,
          weekly_summary: true,
          unusual_transaction_alerts: true,
          unusual_tx_threshold: 500,
          invoice_auto_reminders: true,
          invoice_reminder_days: [0, 3, 7, 14],
        }
      });
    }
    res.json({ success: true, settings: result.rows[0] });
  } catch (err) {
    console.error('GET /api/notification-settings error:', err);
    res.status(500).json({ error: 'Failed to load notification settings' });
  }
});

// ─── PATCH /api/notification-settings ────────────────────
app.patch('/api/notification-settings', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const {
      vat_deadline_reminders,
      weekly_summary,
      unusual_transaction_alerts,
      unusual_tx_threshold,
      invoice_auto_reminders,
      invoice_reminder_days,
    } = req.body;

    await pool.query(`
      INSERT INTO notification_settings
        (user_id, vat_deadline_reminders, weekly_summary,
         unusual_transaction_alerts, unusual_tx_threshold,
         invoice_auto_reminders, invoice_reminder_days)
      VALUES ($1,
        COALESCE($2, true), COALESCE($3, true),
        COALESCE($4, true), COALESCE($5, 500),
        COALESCE($6, true), COALESCE($7, '[0,3,7,14]')
      )
      ON CONFLICT (user_id) DO UPDATE SET
        vat_deadline_reminders     = COALESCE($2, notification_settings.vat_deadline_reminders),
        weekly_summary             = COALESCE($3, notification_settings.weekly_summary),
        unusual_transaction_alerts = COALESCE($4, notification_settings.unusual_transaction_alerts),
        unusual_tx_threshold       = COALESCE($5, notification_settings.unusual_tx_threshold),
        invoice_auto_reminders     = COALESCE($6, notification_settings.invoice_auto_reminders),
        invoice_reminder_days      = COALESCE($7, notification_settings.invoice_reminder_days),
        updated_at = NOW()
    `, [
      userId,
      vat_deadline_reminders ?? null,
      weekly_summary ?? null,
      unusual_transaction_alerts ?? null,
      unusual_tx_threshold ?? null,
      invoice_auto_reminders ?? null,
      invoice_reminder_days ? JSON.stringify(invoice_reminder_days) : null,
    ]);

    const updated = await pool.query(`SELECT * FROM notification_settings WHERE user_id = $1`, [userId]);
    res.json({ success: true, settings: updated.rows[0] });
  } catch (err) {
    console.error('PATCH /api/notification-settings error:', err);
    res.status(500).json({ error: 'Failed to update notification settings' });
  }
});

// ─── GET /i/:token — Public invoice view ─────────────────
app.get('/i/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const inv = await pool.query(
      `SELECT i.*, u.email AS owner_email, u.id AS owner_id
         FROM invoices i
         JOIN users u ON i.user_id = u.id
        WHERE i.view_token = $1`,
      [token]
    );
    if (!inv.rows[0]) return res.status(404).send('<h2>Invoice not found</h2>');

    const invoice = inv.rows[0];
    const [items, profile] = await Promise.all([
      pool.query(`SELECT * FROM invoice_items WHERE invoice_id = $1 ORDER BY sort_order, id`, [invoice.id]),
      getBusinessProfile(invoice.owner_id),
    ]);

    const fmtGBP2 = (n) => `£${parseFloat(n || 0).toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    const fmtDate2 = (d) => d ? new Date(d).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }) : '—';

    const statusBadge = {
      draft: 'background:#f3f4f6;color:#374151',
      sent: 'background:#dbeafe;color:#1d4ed8',
      paid: 'background:#dcfce7;color:#166534',
      overdue: 'background:#fee2e2;color:#991b1b',
    }[invoice.status] || 'background:#f3f4f6;color:#374151';

    const bizName = (profile && profile.business_name) ? profile.business_name : 'FinOwl';
    const pdfLink = `/api/invoices/p/${token}/pdf`;

    const itemRows = items.rows.map(item => `
      <tr>
        <td style="padding:10px 0;border-bottom:1px solid #f0eee9">${item.description}</td>
        <td style="padding:10px 0;border-bottom:1px solid #f0eee9;text-align:center">${parseFloat(item.quantity)}</td>
        <td style="padding:10px 0;border-bottom:1px solid #f0eee9;text-align:right">${fmtGBP2(item.unit_price)}</td>
        <td style="padding:10px 0;border-bottom:1px solid #f0eee9;text-align:right;font-weight:600">${fmtGBP2(item.amount)}</td>
      </tr>
    `).join('');

    const hasBankDetails = profile && (profile.bank_sort_code || profile.bank_account_number);

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${invoice.invoice_number} — Invoice from ${bizName}</title>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { background:#f5f4f1; font-family:'Helvetica Neue',Arial,sans-serif; color:#0a0f1a; padding:24px 16px; }
    .card { max-width:700px; margin:0 auto; background:#fff; border-radius:16px; border:1px solid #e5e2db; overflow:hidden; }
    .card-header { background:#0a0f1a; padding:24px 32px; display:flex; justify-content:space-between; align-items:center; }
    .brand { color:#fff; font-size:20px; font-weight:700; }
    .inv-num { color:#d4920b; font-size:14px; font-weight:600; }
    .body { padding:32px; }
    .status-badge { display:inline-block; padding:4px 12px; border-radius:20px; font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:20px; ${statusBadge} }
    .parties { display:grid; grid-template-columns:1fr 1fr; gap:24px; margin-bottom:24px; }
    .party-block label { font-size:10px; text-transform:uppercase; letter-spacing:0.6px; color:#9ca3af; margin-bottom:6px; display:block; }
    .party-block .name { font-size:15px; font-weight:600; margin-bottom:3px; }
    .party-block .detail { font-size:13px; color:#6b7280; line-height:1.5; }
    .inv-meta { display:grid; grid-template-columns:repeat(3,1fr); gap:16px; background:#f9f8f6; border-radius:10px; padding:16px 20px; margin-bottom:24px; }
    .inv-meta-item label { font-size:10px; text-transform:uppercase; letter-spacing:0.6px; color:#9ca3af; display:block; margin-bottom:4px; }
    .inv-meta-item span { font-size:14px; font-weight:600; }
    table { width:100%; border-collapse:collapse; margin-bottom:16px; }
    th { font-size:10px; text-transform:uppercase; color:#9ca3af; letter-spacing:0.5px; padding-bottom:8px; border-bottom:2px solid #e5e2db; }
    th:last-child, td:last-child { text-align:right; }
    .totals { display:flex; flex-direction:column; align-items:flex-end; gap:8px; margin-top:8px; }
    .total-row { display:flex; gap:40px; font-size:14px; }
    .total-row.grand { font-size:18px; font-weight:700; color:#0a0f1a; padding-top:8px; border-top:2px solid #0a0f1a; margin-top:4px; }
    .total-label { color:#6b7280; }
    .bank-box { background:#f0fdf4; border:1px solid #bbf7d0; border-radius:10px; padding:16px 20px; margin-top:20px; }
    .bank-box h4 { font-size:13px; font-weight:700; color:#166534; margin-bottom:10px; }
    .bank-row { display:flex; gap:12px; font-size:13px; padding:3px 0; }
    .bank-row .k { color:#6b7280; min-width:120px; }
    .notes-box { background:#f9f8f6; border-radius:8px; padding:16px; margin-top:16px; font-size:13px; color:#6b7280; }
    .actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:24px; padding-top:20px; border-top:1px solid #f0eee9; }
    .btn { display:inline-block; padding:11px 22px; border-radius:8px; font-weight:600; font-size:13px; text-decoration:none; cursor:pointer; }
    .btn-pdf { background:#d4920b; color:#fff; border:none; }
    .btn-print { background:#fff; color:#0a0f1a; border:1.5px solid #e5e2db; }
    .footer { text-align:center; font-size:11px; color:#9ca3af; padding:16px 20px; border-top:1px solid #f0eee9; }
    .footer a { color:#d4920b; text-decoration:none; }
    @media print { body { background:#fff; padding:0; } .card { border:none; border-radius:0; } .actions { display:none; } }
    @media (max-width:500px) { .parties, .inv-meta { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <div class="card">
    <div class="card-header">
      <div class="brand">${bizName}</div>
      <div class="inv-num">${invoice.invoice_number}</div>
    </div>
    <div class="body">
      <div class="status-badge">${invoice.status}</div>

      <div class="parties">
        <div class="party-block">
          <label>From</label>
          <div class="name">${bizName}</div>
          ${profile && profile.business_address ? `<div class="detail" style="white-space:pre-line">${profile.business_address}</div>` : ''}
          ${profile && profile.business_email ? `<div class="detail">${profile.business_email}</div>` : ''}
          ${profile && profile.business_phone ? `<div class="detail">${profile.business_phone}</div>` : ''}
        </div>
        <div class="party-block">
          <label>Billed to</label>
          <div class="name">${invoice.client_name}</div>
          ${invoice.client_address ? `<div class="detail" style="white-space:pre-line">${invoice.client_address}</div>` : ''}
          ${invoice.client_email ? `<div class="detail">${invoice.client_email}</div>` : ''}
        </div>
      </div>

      <div class="inv-meta">
        <div class="inv-meta-item"><label>Invoice No.</label><span>${invoice.invoice_number}</span></div>
        <div class="inv-meta-item"><label>Issued</label><span>${fmtDate2(invoice.issue_date)}</span></div>
        <div class="inv-meta-item"><label>Due Date</label><span>${invoice.due_date ? fmtDate2(invoice.due_date) : '—'}</span></div>
      </div>

      <table>
        <thead>
          <tr>
            <th style="text-align:left">Description</th>
            <th style="text-align:center">Qty</th>
            <th style="text-align:right">Unit Price</th>
            <th style="text-align:right">Amount</th>
          </tr>
        </thead>
        <tbody>${itemRows}</tbody>
      </table>

      <div class="totals">
        ${parseFloat(invoice.vat_rate) > 0 ? `
        <div class="total-row"><span class="total-label">Subtotal</span><span>${fmtGBP2(invoice.subtotal)}</span></div>
        <div class="total-row"><span class="total-label">VAT (${invoice.vat_rate}%)</span><span>${fmtGBP2(invoice.vat_amount)}</span></div>
        ` : ''}
        <div class="total-row grand"><span class="total-label">Total Due</span><span>${fmtGBP2(invoice.total)}</span></div>
      </div>

      ${hasBankDetails ? `
      <div class="bank-box">
        <h4>💳 Payment Details</h4>
        ${profile.bank_name ? `<div class="bank-row"><span class="k">Bank</span><span>${profile.bank_name}</span></div>` : ''}
        ${profile.bank_sort_code ? `<div class="bank-row"><span class="k">Sort Code</span><span>${profile.bank_sort_code}</span></div>` : ''}
        ${profile.bank_account_number ? `<div class="bank-row"><span class="k">Account Number</span><span>${profile.bank_account_number}</span></div>` : ''}
        ${profile.bank_reference ? `<div class="bank-row"><span class="k">Reference</span><span>${profile.bank_reference || invoice.invoice_number}</span></div>` : `<div class="bank-row"><span class="k">Reference</span><span>${invoice.invoice_number}</span></div>`}
        ${profile.payment_terms ? `<div class="bank-row" style="margin-top:8px;color:#6b7280;font-size:12px">${profile.payment_terms}</div>` : ''}
      </div>` : ''}

      ${invoice.notes ? `<div class="notes-box"><strong>Notes</strong><br><br>${invoice.notes}</div>` : ''}

      <div class="actions">
        <a href="${pdfLink}" class="btn btn-pdf">⬇ Download PDF</a>
        <button class="btn btn-print" onclick="window.print()">🖨 Print</button>
      </div>
    </div>
    <div class="footer">
      Generated by <a href="https://finowl.co.uk">FinOwl</a> &mdash; smart accounting for UK sole traders
    </div>
  </div>
</body>
</html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (err) {
    console.error('GET /i/:token error:', err);
    res.status(500).send('<h2>Error loading invoice</h2>');
  }
});

// ═══════════════════════════════════════════════════════════
// RECURRING TRANSACTIONS ENGINE
// ═══════════════════════════════════════════════════════════

// Classify frequency from median interval in days
function classifyFrequency(medianDays) {
  if (medianDays >= 5  && medianDays <= 9)   return 'weekly';
  if (medianDays >= 25 && medianDays <= 35)  return 'monthly';
  if (medianDays >= 80 && medianDays <= 100) return 'quarterly';
  if (medianDays >= 10 && medianDays <= 24)  return 'fortnightly';
  return 'irregular';
}

function median(arr) {
  if (!arr.length) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function addExpectedDays(dateStr, days) {
  const d = new Date(dateStr);
  d.setDate(d.getDate() + days);
  return d.toISOString().slice(0, 10);
}

async function detectRecurringPatternsForUser(userId) {
  // Fetch 13 months of transactions (expenses — negative amounts, or consistent positive)
  const txResult = await pool.query(
    `SELECT id, date, amount, merchant_name, description
     FROM transactions
     WHERE user_id = $1 AND date >= NOW() - INTERVAL '13 months'
     ORDER BY date ASC`,
    [userId]
  );

  // Group by normalised merchant key
  const groups = {};
  for (const tx of txResult.rows) {
    const key = normaliseMerchantKey(tx);
    if (!key) continue;
    if (!groups[key]) groups[key] = { display: tx.merchant_name || tx.description, txs: [] };
    groups[key].txs.push(tx);
  }

  let detected = 0;
  for (const [key, group] of Object.entries(groups)) {
    const txs = group.txs; // already sorted by date ASC
    if (txs.length < 3) continue; // Need at least 3 occurrences

    // Check user hasn't explicitly marked this as NOT recurring
    const existingOverride = await pool.query(
      `SELECT user_marked_recurring FROM recurring_patterns WHERE user_id = $1 AND merchant_key = $2`,
      [userId, key]
    );
    if (existingOverride.rows[0]?.user_marked_recurring === false) continue;

    // Calculate intervals (days between consecutive transactions)
    const intervals = [];
    for (let i = 1; i < txs.length; i++) {
      const daysDiff = Math.round(
        (new Date(txs[i].date) - new Date(txs[i - 1].date)) / (1000 * 60 * 60 * 24)
      );
      intervals.push(daysDiff);
    }

    const medianInterval = median(intervals);
    // Filter: intervals must be reasonably consistent (within ±50% of median)
    const consistentIntervals = intervals.filter(d =>
      d >= medianInterval * 0.5 && d <= medianInterval * 1.5
    );
    if (consistentIntervals.length < intervals.length * 0.6) continue; // >40% outliers → skip

    const freq = classifyFrequency(medianInterval);
    if (freq === 'irregular' && medianInterval > 100) continue; // Too irregular

    // Calculate amount stats
    const amounts = txs.map(t => Math.abs(parseFloat(t.amount)));
    const avgAmount = amounts.reduce((s, a) => s + a, 0) / amounts.length;
    const minAmount = Math.min(...amounts);
    const maxAmount = Math.max(...amounts);

    // Amount variance check: reject if max deviates >50% from avg (not a real recurring pattern)
    if (maxAmount > avgAmount * 1.5 || minAmount < avgAmount * 0.5) {
      // Check if at least 80% of amounts are within ±20% of median
      const medianAmt = median(amounts);
      const stable = amounts.filter(a => a >= medianAmt * 0.8 && a <= medianAmt * 1.2);
      if (stable.length < amounts.length * 0.8) continue;
    }

    const lastTx = txs[txs.length - 1];
    const expectedNext = addExpectedDays(lastTx.date, Math.round(medianInterval));

    // Get the most-used category for this merchant
    const catResult = await pool.query(
      `SELECT category_id, COUNT(*) as cnt
       FROM transactions
       WHERE user_id = $1 AND category_id IS NOT NULL
         AND (merchant_name ILIKE $2 OR description ILIKE $2)
       GROUP BY category_id ORDER BY cnt DESC LIMIT 1`,
      [userId, `%${(txs[0].merchant_name || '').split(' ')[0] || key.split(' ')[0]}%`]
    );
    const categoryId = catResult.rows[0]?.category_id || null;

    await pool.query(
      `INSERT INTO recurring_patterns
         (user_id, merchant_key, merchant_display, typical_amount, min_amount, max_amount,
          frequency, avg_interval_days, category_id, transaction_count, first_seen, last_seen,
          expected_next_date, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
       ON CONFLICT (user_id, merchant_key) DO UPDATE SET
         merchant_display   = EXCLUDED.merchant_display,
         typical_amount     = EXCLUDED.typical_amount,
         min_amount         = EXCLUDED.min_amount,
         max_amount         = EXCLUDED.max_amount,
         frequency          = EXCLUDED.frequency,
         avg_interval_days  = EXCLUDED.avg_interval_days,
         category_id        = COALESCE(recurring_patterns.category_id, EXCLUDED.category_id),
         transaction_count  = EXCLUDED.transaction_count,
         first_seen         = EXCLUDED.first_seen,
         last_seen          = EXCLUDED.last_seen,
         expected_next_date = EXCLUDED.expected_next_date,
         updated_at         = NOW()`,
      [
        userId, key, group.display, avgAmount.toFixed(2), minAmount.toFixed(2), maxAmount.toFixed(2),
        freq, Math.round(medianInterval), categoryId, txs.length,
        txs[0].date, lastTx.date, expectedNext
      ]
    );

    // Mark all matching transactions as recurring
    const txIds = txs.map(t => t.id);
    const patternRow = await pool.query(
      `SELECT id FROM recurring_patterns WHERE user_id = $1 AND merchant_key = $2`,
      [userId, key]
    );
    if (patternRow.rows[0]) {
      await pool.query(
        `UPDATE transactions SET is_recurring = true, recurring_pattern_id = $1
         WHERE id = ANY($2::int[]) AND user_id = $3`,
        [patternRow.rows[0].id, txIds, userId]
      );
    }

    detected++;
  }

  return detected;
}

// Check for amount changes and missed payments, send alerts
async function checkRecurringAlerts(userId) {
  const userRow = await pool.query(`SELECT email FROM users WHERE id = $1`, [userId]);
  if (!userRow.rows[0]) return;
  const userEmail = userRow.rows[0].email;

  const notifSettings = await pool.query(
    `SELECT * FROM notification_settings WHERE user_id = $1`, [userId]
  );
  if (notifSettings.rows[0]?.email_enabled === false) return;

  const patterns = await pool.query(
    `SELECT * FROM recurring_patterns
     WHERE user_id = $1 AND is_active = true
       AND (user_marked_recurring IS NULL OR user_marked_recurring = true)`,
    [userId]
  );

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  for (const pattern of patterns.rows) {
    if (!pattern.avg_interval_days) continue;

    // ── 1. Amount change alert ──────────────────────────────
    // Look for a recent transaction matching this pattern
    const recentTx = await pool.query(
      `SELECT * FROM transactions
       WHERE user_id = $1 AND recurring_pattern_id = $2
         AND date >= NOW() - INTERVAL '35 days'
       ORDER BY date DESC LIMIT 1`,
      [userId, pattern.id]
    );

    if (recentTx.rows[0] && pattern.typical_amount) {
      const actualAmt = Math.abs(parseFloat(recentTx.rows[0].amount));
      const typical   = parseFloat(pattern.typical_amount);
      const diff      = Math.abs(actualAmt - typical) / typical;

      if (diff > 0.20 && (!pattern.last_amount_alert_amount ||
          Math.abs(parseFloat(pattern.last_amount_alert_amount) - actualAmt) > 0.01)) {
        // New amount change — send alert
        const direction = actualAmt > typical ? 'increased' : 'decreased';
        await sendAlertEmail(userEmail, 'recurring_amount_change', {
          merchant: pattern.merchant_display,
          typical: typical.toFixed(2),
          actual: actualAmt.toFixed(2),
          direction,
          patternId: pattern.id
        });
        await pool.query(
          `UPDATE recurring_patterns SET last_alert_type = 'amount_change',
           last_amount_alert_amount = $1, last_alert_sent_at = NOW() WHERE id = $2`,
          [actualAmt.toFixed(2), pattern.id]
        );
      }
    }

    // ── 2. Missed payment detection ─────────────────────────
    if (!pattern.expected_next_date) continue;
    const expected = new Date(pattern.expected_next_date);
    expected.setHours(0, 0, 0, 0);
    const daysPastDue = Math.round((today - expected) / (1000 * 60 * 60 * 24));

    // Only alert if 3–14 days past expected and we haven't already sent a missed-payment alert recently
    if (daysPastDue >= 3 && daysPastDue <= 14) {
      const alreadySent = pattern.last_alert_type === 'missed_payment' &&
        pattern.last_alert_sent_at &&
        (today - new Date(pattern.last_alert_sent_at)) < 7 * 24 * 60 * 60 * 1000;
      if (alreadySent) continue;

      // Verify there really is no transaction for this period
      const windowStart = new Date(expected);
      windowStart.setDate(windowStart.getDate() - 5);
      const check = await pool.query(
        `SELECT id FROM transactions
         WHERE user_id = $1 AND recurring_pattern_id = $2 AND date >= $3`,
        [userId, pattern.id, windowStart.toISOString().slice(0, 10)]
      );
      if (check.rows.length > 0) continue; // Payment found, skip

      await sendAlertEmail(userEmail, 'missed_payment', {
        merchant: pattern.merchant_display,
        expectedDate: pattern.expected_next_date,
        daysPastDue,
        typicalAmount: pattern.typical_amount,
        patternId: pattern.id
      });
      await pool.query(
        `UPDATE recurring_patterns SET last_alert_type = 'missed_payment',
         last_alert_sent_at = NOW() WHERE id = $1`,
        [pattern.id]
      );
    }
  }
}

async function sendAlertEmail(to, type, data) {
  let subject, htmlBody;
  if (type === 'recurring_amount_change') {
    subject = `⚠️ ${data.merchant} payment ${data.direction} — was £${data.typical}, now £${data.actual}`;
    htmlBody = `
      <div style="font-family:sans-serif;max-width:560px">
        <h2 style="color:#b45309">Recurring payment amount changed</h2>
        <p>Your payment to <strong>${data.merchant}</strong> has <strong>${data.direction}</strong>.</p>
        <table style="width:100%;border-collapse:collapse">
          <tr><td style="padding:8px;border:1px solid #e5e7eb">Usual amount</td><td style="padding:8px;border:1px solid #e5e7eb">£${data.typical}</td></tr>
          <tr><td style="padding:8px;border:1px solid #e5e7eb">This month</td><td style="padding:8px;border:1px solid #e5e7eb;font-weight:bold;color:#dc2626">£${data.actual}</td></tr>
        </table>
        <p style="margin-top:16px">Worth checking if this is a price change, an error, or a one-off charge.</p>
        <p><a href="https://finowl.co.uk" style="background:#d97706;color:#fff;padding:8px 16px;border-radius:6px;text-decoration:none">View in FinOwl</a></p>
      </div>`;
  } else {
    subject = `⚠️ ${data.merchant} payment may be missing — expected ${data.expectedDate}`;
    htmlBody = `
      <div style="font-family:sans-serif;max-width:560px">
        <h2 style="color:#b45309">Recurring payment not detected</h2>
        <p>Your expected payment to <strong>${data.merchant}</strong> hasn't appeared in your bank feed.</p>
        <table style="width:100%;border-collapse:collapse">
          <tr><td style="padding:8px;border:1px solid #e5e7eb">Expected on</td><td style="padding:8px;border:1px solid #e5e7eb">${data.expectedDate}</td></tr>
          <tr><td style="padding:8px;border:1px solid #e5e7eb">Days overdue</td><td style="padding:8px;border:1px solid #e5e7eb;font-weight:bold;color:#dc2626">${data.daysPastDue} days</td></tr>
          ${data.typicalAmount ? `<tr><td style="padding:8px;border:1px solid #e5e7eb">Typical amount</td><td style="padding:8px;border:1px solid #e5e7eb">£${parseFloat(data.typicalAmount).toFixed(2)}</td></tr>` : ''}
        </table>
        <p style="margin-top:16px">This could mean the payment was missed, cancelled, or your bank feed needs a sync.</p>
        <p><a href="https://finowl.co.uk" style="background:#d97706;color:#fff;padding:8px 16px;border-radius:6px;text-decoration:none">View in FinOwl</a></p>
      </div>`;
  }

  return sendEmail({ to, subject, htmlBody, metadata: { type: 'recurring_alert' } });
}

// ═══════════════════════════════════════════════════════════
// RECURRING PATTERNS API
// ═══════════════════════════════════════════════════════════

// GET /api/recurring — list all detected patterns for the user
app.get('/api/recurring', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const result = await pool.query(
      `SELECT rp.*, c.name as category_name, c.color as category_color, c.icon as category_icon
       FROM recurring_patterns rp
       LEFT JOIN categories c ON rp.category_id = c.id
       WHERE rp.user_id = $1
         AND (rp.user_marked_recurring IS NULL OR rp.user_marked_recurring = true)
         AND rp.is_active = true
       ORDER BY rp.typical_amount DESC NULLS LAST`,
      [userId]
    );
    res.json({ patterns: result.rows });
  } catch (err) {
    console.error('GET /api/recurring error:', err);
    res.status(500).json({ error: 'Failed to fetch recurring patterns' });
  }
});

// POST /api/recurring/detect — run detection for the current user
app.post('/api/recurring/detect', authenticateToken, requireOwner, async (req, res) => {
  try {
    const userId = req.user.userId;
    const detected = await detectRecurringPatternsForUser(userId);
    const countResult = await pool.query(
      `SELECT COUNT(*) FROM recurring_patterns WHERE user_id = $1 AND is_active = true
         AND (user_marked_recurring IS NULL OR user_marked_recurring = true)`,
      [userId]
    );
    res.json({ detected, total: parseInt(countResult.rows[0].count) });
  } catch (err) {
    console.error('POST /api/recurring/detect error:', err);
    res.status(500).json({ error: 'Detection failed' });
  }
});

// PATCH /api/recurring/:id — update category or user override
app.patch('/api/recurring/:id', authenticateToken, requireOwner, async (req, res) => {
  try {
    const userId = req.user.userId;
    const patternId = parseInt(req.params.id);
    const { categoryId, userMarkedRecurring } = req.body;

    const existing = await pool.query(
      `SELECT * FROM recurring_patterns WHERE id = $1 AND user_id = $2`,
      [patternId, userId]
    );
    if (!existing.rows[0]) return res.status(404).json({ error: 'Pattern not found' });

    const updates = [];
    const params = [];
    let idx = 1;

    if (categoryId !== undefined) {
      updates.push(`category_id = $${idx++}`);
      params.push(categoryId || null);
    }
    if (userMarkedRecurring !== undefined) {
      updates.push(`user_marked_recurring = $${idx++}`);
      params.push(userMarkedRecurring);
      // If user marks as not recurring, update the transactions too
      if (userMarkedRecurring === false) {
        await pool.query(
          `UPDATE transactions SET is_recurring = false, recurring_pattern_id = NULL
           WHERE recurring_pattern_id = $1 AND user_id = $2`,
          [patternId, userId]
        );
      }
    }

    if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });

    updates.push(`updated_at = NOW()`);
    params.push(patternId, userId);
    const result = await pool.query(
      `UPDATE recurring_patterns SET ${updates.join(', ')}
       WHERE id = $${idx++} AND user_id = $${idx} RETURNING *`,
      params
    );

    res.json({ pattern: result.rows[0] });
  } catch (err) {
    console.error('PATCH /api/recurring/:id error:', err);
    res.status(500).json({ error: 'Failed to update pattern' });
  }
});

// PATCH /api/transactions/:id/recurring — user manually marks/unmarks a transaction as recurring
app.patch('/api/transactions/:id/recurring', authenticateToken, requireOwner, async (req, res) => {
  try {
    const userId = req.user.userId;
    const txId = parseInt(req.params.id);
    const { isRecurring } = req.body;

    const tx = await pool.query(
      `SELECT * FROM transactions WHERE id = $1 AND user_id = $2`, [txId, userId]
    );
    if (!tx.rows[0]) return res.status(404).json({ error: 'Transaction not found' });

    if (isRecurring) {
      // Mark as recurring — create or find a pattern for this merchant
      const merchantKey = normaliseMerchantKey(tx.rows[0]);
      const merchantDisplay = tx.rows[0].merchant_name || tx.rows[0].description || merchantKey;

      await pool.query(
        `INSERT INTO recurring_patterns
           (user_id, merchant_key, merchant_display, typical_amount, frequency,
            user_marked_recurring, transaction_count, first_seen, last_seen, updated_at)
         VALUES ($1, $2, $3, $4, 'manual', true, 1, $5, $5, NOW())
         ON CONFLICT (user_id, merchant_key) DO UPDATE SET
           user_marked_recurring = true, updated_at = NOW()`,
        [userId, merchantKey, merchantDisplay, Math.abs(parseFloat(tx.rows[0].amount)), tx.rows[0].date]
      );

      const patRow = await pool.query(
        `SELECT id FROM recurring_patterns WHERE user_id = $1 AND merchant_key = $2`, [userId, merchantKey]
      );
      if (patRow.rows[0]) {
        await pool.query(
          `UPDATE transactions SET is_recurring = true, recurring_pattern_id = $1
           WHERE id = $2 AND user_id = $3`,
          [patRow.rows[0].id, txId, userId]
        );
      }
    } else {
      // Unmark
      await pool.query(
        `UPDATE transactions SET is_recurring = false, recurring_pattern_id = NULL
         WHERE id = $1 AND user_id = $2`,
        [txId, userId]
      );
      // If there's a pattern, mark user override as not-recurring if this was a manual pattern
      if (tx.rows[0].recurring_pattern_id) {
        await pool.query(
          `UPDATE recurring_patterns SET user_marked_recurring = false, updated_at = NOW()
           WHERE id = $1 AND user_id = $2 AND frequency = 'manual'`,
          [tx.rows[0].recurring_pattern_id, userId]
        );
      }
    }

    const updated = await pool.query(`SELECT * FROM transactions WHERE id = $1`, [txId]);
    res.json({ transaction: updated.rows[0] });
  } catch (err) {
    console.error('PATCH /api/transactions/:id/recurring error:', err);
    res.status(500).json({ error: 'Failed to update recurring status' });
  }
});

// ─── Run recurring detection in daily sync ───────────────
// Hooks into the existing daily sync — run after bank sync
function scheduleRecurringDetection() {
  const run = async () => {
    console.log('[Recurring] Running daily pattern detection...');
    try {
      // Get all users with transactions
      const users = await pool.query(
        `SELECT DISTINCT user_id FROM transactions WHERE date >= NOW() - INTERVAL '13 months'`
      );
      for (const row of users.rows) {
        try {
          const n = await detectRecurringPatternsForUser(row.user_id);
          if (n > 0) console.log(`[Recurring] Detected ${n} patterns for user ${row.user_id}`);
          await checkRecurringAlerts(row.user_id);
        } catch (err) {
          console.error(`[Recurring] Error for user ${row.user_id}:`, err.message);
        }
      }
    } catch (err) {
      console.error('[Recurring] Daily detection error:', err.message);
    }
  };

  // Run 60s after startup, then every 24h
  setTimeout(() => {
    run();
    setInterval(run, 24 * 60 * 60 * 1000);
  }, 60000);
}
scheduleRecurringDetection();

// ─── Analytics API ─────────────────────────────────────
const { recordPageView, recordEvent, getAnalyticsSummary } = require('./services/analytics');

// POST /api/analytics/pageview — record a page view
app.post('/api/analytics/pageview', async (req, res) => {
  try {
    const { path, referrer, sessionId, utmParams = {}, userId } = req.body;
    await recordPageView({
      userId: userId || null,
      sessionId: sessionId || '',
      path: path || req.path || '',
      referrer: referrer || req.get('Referrer') || '',
      utmParams,
      userAgent: req.get('User-Agent') || '',
      ipAddress: req.ip || req.connection?.remoteAddress || '',
    });
    res.json({ success: true });
  } catch (err) {
    console.error('[Analytics] pageview error:', err.message);
    res.status(500).json({ error: 'Failed to record page view' });
  }
});

// POST /api/analytics/event — record a custom event
app.post('/api/analytics/event', async (req, res) => {
  try {
    const { eventName, properties = {}, sessionId, utmParams = {}, userId } = req.body;
    if (!eventName) return res.status(400).json({ error: 'eventName is required' });
    await recordEvent({
      userId: userId || null,
      sessionId: sessionId || '',
      eventName,
      properties,
      utmParams,
      userAgent: req.get('User-Agent') || '',
      ipAddress: req.ip || req.connection?.remoteAddress || '',
    });
    res.json({ success: true });
  } catch (err) {
    console.error('[Analytics] event error:', err.message);
    res.status(500).json({ error: 'Failed to record event' });
  }
});

// GET /api/analytics — analytics summary (public, no auth needed for now)
app.get('/api/analytics', async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const summary = await getAnalyticsSummary({ startDate, endDate });
    res.json({ success: true, ...summary });
  } catch (err) {
    console.error('[Analytics] summary error:', err.message);
    res.status(500).json({ error: 'Failed to get analytics' });
  }
});

// ═══════════════════════════════════════════════════════════
// EXPENSES & MILEAGE API
// ═══════════════════════════════════════════════════════════

// GET /api/expenses/summary?year=YYYY — summary stats for mileage + manual expenses view
app.get('/api/expenses/summary', authenticateToken, async (req, res) => {
  try {
    const year = parseInt(req.query.year) || new Date().getFullYear();
    const userId = req.user.userId;
    const startDate = `${year}-01-01`;
    const endDate = `${year}-12-31`;

    // Mileage summary
    const mileageRes = await pool.query(`
      SELECT
        COALESCE(SUM(miles), 0) AS total_miles,
        COUNT(*) AS trip_count
      FROM mileage_trips
      WHERE user_id = $1 AND date >= $2 AND date <= $3
    `, [userId, startDate, endDate]);

    const totalMiles = parseFloat(mileageRes.rows[0]?.total_miles || 0);
    const tripCount = parseInt(mileageRes.rows[0]?.trip_count || 0);

    // HMRC approved mileage rates: 45p/mile first 10,000 miles, 25p/mile thereafter
    const first10kMiles = Math.min(totalMiles, 10000);
    const above10kMiles = Math.max(0, totalMiles - 10000);
    const mileageDeduction = (first10kMiles * 0.45) + (above10kMiles * 0.25);

    // Manual expenses summary
    const manualRes = await pool.query(`
      SELECT
        COALESCE(SUM(CASE WHEN is_allowable = true THEN amount ELSE 0 END), 0) AS allowable,
        COALESCE(SUM(CASE WHEN is_allowable = false THEN amount ELSE 0 END), 0) AS disallowable,
        COUNT(*) AS count
      FROM manual_expenses
      WHERE user_id = $1 AND date >= $2 AND date <= $3
    `, [userId, startDate, endDate]);

    const allowable = parseFloat(manualRes.rows[0]?.allowable || 0);
    const disallowable = parseFloat(manualRes.rows[0]?.disallowable || 0);
    const manualCount = parseInt(manualRes.rows[0]?.count || 0);

    // Total claimable = mileage deduction + allowable manual expenses
    const totalClaimable = mileageDeduction + allowable;

    res.json({
      mileage: {
        total_miles: totalMiles,
        trip_count: tripCount,
        deduction: parseFloat(mileageDeduction.toFixed(2)),
      },
      manual_expenses: {
        allowable,
        disallowable,
        count: manualCount,
      },
      summary: {
        total_claimable: parseFloat(totalClaimable.toFixed(2)),
      },
    });
  } catch (err) {
    console.error('[Expenses Summary] error:', err.message);
    res.status(500).json({ error: 'Failed to load expenses summary' });
  }
});

// GET /api/mileage?year=YYYY — all mileage trips for the year
app.get('/api/mileage', authenticateToken, async (req, res) => {
  try {
    const year = parseInt(req.query.year) || new Date().getFullYear();
    const userId = req.user.userId;
    const startDate = `${year}-01-01`;
    const endDate = `${year}-12-31`;

    const tripsRes = await pool.query(`
      SELECT id, date, start_location, end_location, miles, purpose, notes, created_at
      FROM mileage_trips
      WHERE user_id = $1 AND date >= $2 AND date <= $3
      ORDER BY date DESC
    `, [userId, startDate, endDate]);

    // Compute per-trip deduction and rate
    const trips = tripsRes.rows.map(trip => {
      const miles = parseFloat(trip.miles);
      // Running total for this user's trips (approximate — using all-time to determine rate)
      return {
        ...trip,
        miles,
        _deduction: miles <= 10000 ? (miles * 0.45) : (miles * 0.25),
        _rate: miles <= 10000 ? '45p' : '25p',
      };
    });

    // Overall totals for the year (for summary row)
    const summaryRes = await pool.query(`
      SELECT COALESCE(SUM(miles), 0) AS total_miles, COUNT(*) AS trip_count
      FROM mileage_trips
      WHERE user_id = $1 AND date >= $2 AND date <= $3
    `, [userId, startDate, endDate]);

    const totalMiles = parseFloat(summaryRes.rows[0]?.total_miles || 0);
    const totalDeduction = totalMiles <= 10000 ? totalMiles * 0.45 : totalMiles * 0.25;

    res.json({
      trips,
      summary: {
        total_miles: totalMiles,
        total_deduction: parseFloat(totalDeduction.toFixed(2)),
        trip_count: parseInt(summaryRes.rows[0]?.trip_count || 0),
      },
    });
  } catch (err) {
    console.error('[Mileage GET] error:', err.message);
    res.status(500).json({ error: 'Failed to load mileage trips' });
  }
});

// POST /api/mileage — create a mileage trip
app.post('/api/mileage', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { date, start_location, end_location, miles, purpose, notes } = req.body;

    if (!date || !start_location || !end_location || !miles || !purpose) {
      return res.status(400).json({ error: 'date, start_location, end_location, miles, and purpose are required' });
    }
    const milesNum = parseFloat(miles);
    if (isNaN(milesNum) || milesNum <= 0) {
      return res.status(400).json({ error: 'miles must be a positive number' });
    }

    const result = await pool.query(
      `INSERT INTO mileage_trips (user_id, date, start_location, end_location, miles, purpose, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [userId, date, start_location.trim(), end_location.trim(), milesNum, purpose.trim(), (notes || '').trim()]
    );
    res.json({ success: true, trip: result.rows[0] });
  } catch (err) {
    console.error('[Mileage POST] error:', err.message);
    res.status(500).json({ error: 'Failed to create mileage trip' });
  }
});

// DELETE /api/mileage/:id — delete a mileage trip
app.delete('/api/mileage/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { id } = req.params;
    const result = await pool.query(
      `DELETE FROM mileage_trips WHERE id = $1 AND user_id = $2 RETURNING id`,
      [id, userId]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Mileage trip not found' });
    }
    res.json({ success: true });
  } catch (err) {
    console.error('[Mileage DELETE] error:', err.message);
    res.status(500).json({ error: 'Failed to delete mileage trip' });
  }
});

// GET /api/manual-expenses?year=YYYY — all manual expenses for the year
app.get('/api/manual-expenses', authenticateToken, async (req, res) => {
  try {
    const year = parseInt(req.query.year) || new Date().getFullYear();
    const userId = req.user.userId;
    const startDate = `${year}-01-01`;
    const endDate = `${year}-12-31`;

    const result = await pool.query(`
      SELECT me.*, c.name AS category_name, c.icon AS category_icon
      FROM manual_expenses me
      LEFT JOIN categories c ON me.category_id = c.id
      WHERE me.user_id = $1 AND me.date >= $2 AND me.date <= $3
      ORDER BY me.date DESC
    `, [userId, startDate, endDate]);

    res.json({ expenses: result.rows });
  } catch (err) {
    console.error('[Manual Expenses GET] error:', err.message);
    res.status(500).json({ error: 'Failed to load manual expenses' });
  }
});

// POST /api/manual-expenses — create a manual expense
app.post('/api/manual-expenses', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { date, description, amount, category_id, is_allowable, receipt_url, notes } = req.body;

    if (!date || !description || amount == null) {
      return res.status(400).json({ error: 'date, description, and amount are required' });
    }
    const amountNum = parseFloat(amount);
    if (isNaN(amountNum) || amountNum <= 0) {
      return res.status(400).json({ error: 'amount must be a positive number' });
    }

    const result = await pool.query(
      `INSERT INTO manual_expenses (user_id, date, description, amount, category_id, is_allowable, receipt_url, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [userId, date, description.trim(), amountNum, category_id || null, is_allowable !== false, receipt_url || null, (notes || '').trim()]
    );
    logAuditEvent({
      userId,
      eventType: 'expense_created',
      entityType: 'expense',
      entityId: result.rows[0].id,
      details: { description, amount: amountNum, date, is_allowable: is_allowable !== false },
      req,
    });
    res.json({ success: true, expense: result.rows[0] });
  } catch (err) {
    console.error('[Manual Expenses POST] error:', err.message);
    res.status(500).json({ error: 'Failed to create manual expense' });
  }
});

// DELETE /api/manual-expenses/:id — delete a manual expense
app.delete('/api/manual-expenses/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { id } = req.params;
    const result = await pool.query(
      `DELETE FROM manual_expenses WHERE id = $1 AND user_id = $2 RETURNING id`,
      [id, userId]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Manual expense not found' });
    }
    logAuditEvent({
      userId,
      eventType: 'expense_deleted',
      entityType: 'expense',
      entityId: parseInt(id),
      details: {},
      req,
    });
    res.json({ success: true });
  } catch (err) {
    console.error('[Manual Expenses DELETE] error:', err.message);
    res.status(500).json({ error: 'Failed to delete manual expense' });
  }
});

// ═══════════════════════════════════════════════════════════
// TEAM ACCESS
// ═══════════════════════════════════════════════════════════

// Serve the accept invite page at /accept
app.get('/accept', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'accept.html'));
});

// ─── Team Invite Email (rich template, uses email.js) ──
async function sendTeamInviteEmail({ to, ownerEmail, inviteUrl }) {
  const htmlBody = wrapHtml(`
    <p>${ownerEmail} has invited you to view their FinOwl account as a read-only accountant.</p>
    <p style="display:inline-block;background:#f0f9ff;color:#0369a1;border:1px solid #bae6fd;border-radius:8px;padding:8px 14px;font-size:13px;font-weight:500;margin:16px 0">
      &#x1F441;&#xFE0F; Read-only access &mdash; you cannot edit any data
    </p>
    <p style="font-size:14px;color:#374151;line-height:1.6;margin-bottom:8px">
      You'll be able to view their transactions, VAT returns, expenses, mileage records, receipts, invoices, and financial reports.
    </p>
    <a href="${inviteUrl}" style="display:inline-block;background:#d4920b;color:#fff;text-decoration:none;padding:14px 28px;border-radius:8px;font-weight:600;font-size:15px;margin:20px 0">Accept &amp; View Books &rarr;</a>
    <p style="font-size:12px;color:#9ca3af;margin-top:8px">Or copy this link: <a href="${inviteUrl}" style="color:#d4920b">${inviteUrl}</a></p>
    <p style="font-size:12px;color:#9ca3af;margin-top:16px">If you weren't expecting this invite, you can safely ignore this email.</p>
  `, { subtitle: "You've been invited to FinOwl" });

  return sendEmail({
    to,
    subject: `${ownerEmail} invited you to their FinOwl account`,
    htmlBody,
    metadata: { type: 'team_invite' },
  });
}

// GET /api/team/members — list team members for this owner
app.get('/api/team/members', authenticateToken, requireOwner, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, role, invite_token, invited_at, accepted_at
       FROM team_members WHERE owner_id = $1 ORDER BY invited_at DESC`,
      [req.user.userId]
    );
    res.json({ members: result.rows });
  } catch (err) {
    console.error('[Team] GET members error:', err.message);
    res.status(500).json({ error: 'Failed to load team members' });
  }
});

// POST /api/team/invite — send accountant invite
app.post('/api/team/invite', authenticateToken, requireOwner, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    const normalised = email.toLowerCase().trim();
    const inviteToken = crypto.randomBytes(48).toString('hex');

    // Upsert: if already invited, refresh token
    const result = await pool.query(
      `INSERT INTO team_members (owner_id, email, role, invite_token, invited_at, accepted_at)
       VALUES ($1, $2, 'accountant', $3, NOW(), NULL)
       ON CONFLICT (owner_id, LOWER(email))
       DO UPDATE SET invite_token = $3, invited_at = NOW(), accepted_at = NULL
       RETURNING *`,
      [req.user.userId, normalised, inviteToken]
    );

    const member = result.rows[0];

    // Get owner email for the invite email
    const ownerResult = await pool.query('SELECT email FROM users WHERE id = $1', [req.user.userId]);
    const ownerEmail = ownerResult.rows[0]?.email || 'your FinOwl client';

    const baseUrl = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
    const inviteUrl = `${baseUrl}/accept?token=${inviteToken}`;

    // Send email (non-blocking)
    sendTeamInviteEmail({ to: normalised, ownerEmail, inviteUrl }).catch(err => {
      console.warn('[Team] Invite email failed (non-fatal):', err.message);
    });

    res.json({ success: true, member, inviteUrl });
  } catch (err) {
    console.error('[Team] POST invite error:', err.message);
    res.status(500).json({ error: 'Failed to send invite' });
  }
});

// DELETE /api/team/:id — revoke team member access
app.delete('/api/team/:id', authenticateToken, requireOwner, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM team_members WHERE id = $1 AND owner_id = $2 RETURNING id, email`,
      [req.params.id, req.user.userId]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Team member not found' });
    }
    res.json({ success: true });
  } catch (err) {
    console.error('[Team] DELETE member error:', err.message);
    res.status(500).json({ error: 'Failed to revoke access' });
  }
});

// GET /api/team/accept — accept an invite, return JWT
app.get('/api/team/accept', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'Token required' });

    const result = await pool.query(
      `SELECT tm.*, u.email AS owner_email
       FROM team_members tm
       JOIN users u ON tm.owner_id = u.id
       WHERE tm.invite_token = $1`,
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Invite not found or already revoked' });
    }

    const member = result.rows[0];

    // Mark as accepted (idempotent — does not overwrite first acceptance date)
    await pool.query(
      `UPDATE team_members SET accepted_at = COALESCE(accepted_at, NOW()) WHERE id = $1`,
      [member.id]
    );

    // Issue JWT — userId is the OWNER's id so all data queries return owner's data
    const jwtToken = jwt.sign(
      { userId: member.owner_id, email: member.email, role: 'accountant', ownerId: member.owner_id },
      JWT_SECRET,
      { expiresIn: '90d' }
    );

    res.json({
      token: jwtToken,
      user: {
        id: member.owner_id,
        email: member.email,
        role: 'accountant',
        ownerEmail: member.owner_email,
      },
    });
  } catch (err) {
    console.error('[Team] Accept invite error:', err.message);
    res.status(500).json({ error: 'Failed to accept invite' });
  }
});

// ═══════════════════════════════════════════════════════════
// AI CHAT ASSISTANT
// ═══════════════════════════════════════════════════════════

// POST /api/chat — AI assistant with full financial context
app.post('/api/chat', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { message, history = [] } = req.body;

    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return res.status(400).json({ error: 'Message is required' });
    }
    if (!process.env.OPENAI_API_KEY) {
      return res.status(503).json({ error: 'AI assistant is not configured' });
    }

    // ── Gather financial context ──────────────────────────
    const now = new Date();
    const currentYear = now.getFullYear();
    const currentMonth = (now.getMonth() + 1).toString().padStart(2, '0');

    // Tax year boundaries (UK: 6 Apr – 5 Apr)
    const taxYearStart = now.getMonth() >= 3
      ? `${currentYear}-04-06`
      : `${currentYear - 1}-04-06`;
    const taxYearEnd = now.getMonth() >= 3
      ? `${currentYear + 1}-04-05`
      : `${currentYear}-04-05`;

    // Current quarter boundaries
    const quarterMonth = now.getMonth();
    let qStart, qEnd;
    if (quarterMonth >= 0 && quarterMonth <= 2) { qStart = `${currentYear}-01-01`; qEnd = `${currentYear}-03-31`; }
    else if (quarterMonth >= 3 && quarterMonth <= 5) { qStart = `${currentYear}-04-01`; qEnd = `${currentYear}-06-30`; }
    else if (quarterMonth >= 6 && quarterMonth <= 8) { qStart = `${currentYear}-07-01`; qEnd = `${currentYear}-09-30`; }
    else { qStart = `${currentYear}-10-01`; qEnd = `${currentYear}-12-31`; }

    // Fetch all context in parallel
    const [txRes, catRes, monthlyRes, taxForecastRes, vatRes] = await Promise.all([
      // Recent 50 transactions
      pool.query(`
        SELECT t.date, t.description, t.merchant_name, t.amount,
               c.name AS category, c.is_income
        FROM transactions t
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = $1
        ORDER BY t.date DESC, t.id DESC
        LIMIT 50
      `, [userId]),

      // Category spending breakdown (tax year)
      pool.query(`
        SELECT c.name, c.is_income,
               COALESCE(SUM(CASE WHEN t.amount > 0 THEN t.amount ELSE 0 END), 0) AS income_total,
               COALESCE(SUM(CASE WHEN t.amount < 0 THEN ABS(t.amount) ELSE 0 END), 0) AS expense_total,
               COUNT(t.id) AS tx_count
        FROM transactions t
        JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3
        GROUP BY c.id, c.name, c.is_income
        ORDER BY expense_total DESC
      `, [userId, taxYearStart, taxYearEnd]),

      // Monthly income/expense summary (last 6 months)
      pool.query(`
        SELECT TO_CHAR(date, 'YYYY-MM') AS month,
               COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) AS income,
               COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) AS expenses
        FROM transactions
        WHERE user_id = $1 AND date >= NOW() - INTERVAL '6 months'
        GROUP BY TO_CHAR(date, 'YYYY-MM')
        ORDER BY month DESC
      `, [userId]),

      // Tax year totals for income tax estimate
      pool.query(`
        SELECT
          COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) AS gross_income,
          COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) AS gross_expenses,
          COUNT(*) AS total_transactions
        FROM transactions
        WHERE user_id = $1 AND date >= $2 AND date <= $3
      `, [userId, taxYearStart, taxYearEnd]),

      // VAT summary for current quarter
      pool.query(`
        SELECT
          COALESCE(SUM(CASE WHEN c.vat_rate = 20 AND c.is_income = true THEN t.amount * 0.20/1.20 ELSE 0 END), 0) AS vat_on_sales,
          COALESCE(SUM(CASE WHEN c.vat_rate = 20 AND c.is_income = false THEN ABS(t.amount) * 0.20/1.20 ELSE 0 END), 0) AS vat_on_purchases
        FROM transactions t
        JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3
      `, [userId, qStart, qEnd]),
    ]);

    // ── Build financial context string ───────────────────
    const tf = taxForecastRes.rows[0];
    const grossIncome = parseFloat(tf.gross_income);
    const grossExpenses = parseFloat(tf.gross_expenses);
    const netProfit = grossIncome - grossExpenses;
    const txCount = parseInt(tf.total_transactions);

    // Simple UK income tax estimate on net profit
    const PA = 12570, BR_TOP = 50270, HR_TOP = 125140;
    const taxable = Math.max(0, netProfit - PA);
    const basicTax = Math.min(taxable, BR_TOP - PA) * 0.20;
    const higherTax = Math.max(0, Math.min(taxable - (BR_TOP - PA), HR_TOP - BR_TOP)) * 0.40;
    const additionalTax = Math.max(0, taxable - (HR_TOP - PA)) * 0.45;
    const incomeTax = basicTax + higherTax + additionalTax;
    const ni4 = Math.max(0, Math.min(netProfit - 12570, 37700)) * 0.06 + Math.max(0, netProfit - 50270) * 0.02;
    const estimatedTax = incomeTax + ni4;

    const vatData = vatRes.rows[0];
    const vatOnSales = parseFloat(vatData.vat_on_sales).toFixed(2);
    const vatOnPurchases = parseFloat(vatData.vat_on_purchases).toFixed(2);
    const netVat = (parseFloat(vatData.vat_on_sales) - parseFloat(vatData.vat_on_purchases)).toFixed(2);

    const fmt = n => `£${Math.abs(Number(n)).toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

    // Recent transactions context (top 20 for brevity)
    const recentTxLines = txRes.rows.slice(0, 20).map(t =>
      `  ${t.date} | ${t.merchant_name || t.description || 'Unknown'} | ${t.amount >= 0 ? '+' : ''}${fmt(t.amount)} | ${t.category || 'Uncategorised'}`
    ).join('\n');

    // Category breakdown
    const catLines = catRes.rows.filter(c => c.expense_total > 0 || c.income_total > 0).slice(0, 15).map(c => {
      if (c.is_income) return `  ${c.name}: income ${fmt(c.income_total)} (${c.tx_count} txns)`;
      return `  ${c.name}: expenses ${fmt(c.expense_total)} (${c.tx_count} txns)`;
    }).join('\n');

    // Monthly summary
    const monthlyLines = monthlyRes.rows.map(m =>
      `  ${m.month}: income ${fmt(m.income)}, expenses ${fmt(m.expenses)}, net ${fmt(parseFloat(m.income) - parseFloat(m.expenses))}`
    ).join('\n');

    const systemPrompt = `You are FinOwl's AI bookkeeping assistant for a UK sole trader. You have access to their real financial data and can answer questions about their books, transactions, tax, and VAT.

CURRENT DATE: ${now.toISOString().substring(0, 10)}
TAX YEAR: ${taxYearStart} to ${taxYearEnd}

=== FINANCIAL SUMMARY (Current Tax Year) ===
Total Income: ${fmt(grossIncome)}
Total Expenses: ${fmt(grossExpenses)}
Net Profit: ${fmt(netProfit)}
Total Transactions: ${txCount}
Estimated Income Tax: ${fmt(incomeTax)}
Estimated NI (Class 4): ${fmt(ni4)}
Estimated Total HMRC Liability: ${fmt(estimatedTax)}

=== CURRENT QUARTER VAT (${qStart} to ${qEnd}) ===
VAT on Sales (Output Tax): £${vatOnSales}
VAT on Purchases (Input Tax): £${vatOnPurchases}
Net VAT Payable: £${netVat}

=== SPENDING BY CATEGORY (Tax Year) ===
${catLines || '  No categorised transactions yet'}

=== MONTHLY PERFORMANCE (Last 6 Months) ===
${monthlyLines || '  No recent transactions'}

=== MOST RECENT TRANSACTIONS (Last 20) ===
${recentTxLines || '  No transactions found'}

=== INSTRUCTIONS ===
- Answer questions about the user's finances using the data above
- Be specific with amounts and dates from the actual data
- For UK tax questions, refer to current HMRC rules (Personal Allowance £12,570, basic rate 20%, higher rate 40%)
- Keep answers concise and actionable — sole traders want plain English, not jargon
- If asked about something not in the data (e.g., a specific transaction you can't find), be honest about what you can see
- NEVER give advice that requires a qualified accountant — always add "check with your accountant for personalised advice" when relevant
- If the data shows no transactions, explain they need to connect a bank account or import transactions first
- You are NOT a financial adviser. End complex tax answers with a brief disclaimer`;

    // ── Build messages array ─────────────────────────────
    const messages = [
      { role: 'system', content: systemPrompt },
    ];

    // Add conversation history (limit to last 10 exchanges to control context size)
    const recentHistory = history.slice(-10);
    for (const h of recentHistory) {
      if (h.role && h.content && ['user', 'assistant'].includes(h.role)) {
        messages.push({ role: h.role, content: String(h.content).substring(0, 2000) });
      }
    }

    messages.push({ role: 'user', content: message.trim().substring(0, 1000) });

    // ── Call OpenAI ──────────────────────────────────────
    const completion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages,
      max_tokens: 600,
      temperature: 0.3,
    });

    const reply = completion.choices[0]?.message?.content || 'Sorry, I couldn\'t generate a response. Please try again.';

    res.json({ success: true, reply, usage: completion.usage });
  } catch (err) {
    console.error('[Chat] Error:', err.message);
    res.status(500).json({ error: 'Failed to get AI response', details: err.message });
  }
});

// ═══════════════════════════════════════════════════════════
// HMRC GOVERNMENT GATEWAY OAUTH (MTD VAT)
// ═══════════════════════════════════════════════════════════

const HMRC_CLIENT_ID = process.env.HMRC_CLIENT_ID || '';
const HMRC_CLIENT_SECRET = process.env.HMRC_CLIENT_SECRET || '';
// Sandbox credentials from developer.service.hmrc.gov.uk - FinOwl app
// Set HMRC_SANDBOX=false in production to switch to live API
const HMRC_SANDBOX = (process.env.HMRC_SANDBOX || 'true') !== 'false';
const HMRC_API_HOST = HMRC_SANDBOX
  ? 'test-api.service.hmrc.gov.uk'
  : 'api.service.hmrc.gov.uk';

// ─── HMRC HTTPS helper (reuses same pattern as TrueLayer) ──
// Returns { status, headers, body } — headers needed for Receipt-ID on submission responses
function hmrcRequest(host, path, method, reqHeaders, body) {
  return new Promise((resolve, reject) => {
    const opts = { hostname: host, path, method, headers: reqHeaders || {} };
    const req = https.request(opts, (res) => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = data; }
        resolve({ status: res.statusCode, headers: res.headers || {}, body: parsed });
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// Exchange authorization code for HMRC access + refresh tokens
async function hmrcExchangeCode(code, redirectUri) {
  const params = new URLSearchParams({
    client_id: HMRC_CLIENT_ID,
    client_secret: HMRC_CLIENT_SECRET,
    grant_type: 'authorization_code',
    redirect_uri: redirectUri,
    code,
  }).toString();

  const res = await hmrcRequest(HMRC_API_HOST, '/oauth/token', 'POST', {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': Buffer.byteLength(params),
  }, params);

  if (res.status !== 200) {
    throw new Error(`HMRC token exchange failed (${res.status}): ${JSON.stringify(res.body)}`);
  }
  return res.body; // { access_token, refresh_token, expires_in, token_type, scope }
}

// Refresh an expired HMRC access token using a refresh token
async function hmrcRefreshTokens(refreshTokenEnc) {
  const refreshToken = decryptToken(refreshTokenEnc);
  if (!refreshToken) throw new Error('No refresh token available');

  const params = new URLSearchParams({
    client_id: HMRC_CLIENT_ID,
    client_secret: HMRC_CLIENT_SECRET,
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
  }).toString();

  const res = await hmrcRequest(HMRC_API_HOST, '/oauth/token', 'POST', {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': Buffer.byteLength(params),
  }, params);

  if (res.status !== 200) {
    throw new Error(`HMRC token refresh failed (${res.status}): ${JSON.stringify(res.body)}`);
  }
  return res.body;
}

// Fetch, refresh if needed, and return a valid HMRC access token for a user.
// Auto-refreshes when < 30 minutes remain (i.e. at the 3.5-hour mark for 4-hour tokens).
async function getValidHmrcToken(userId) {
  const result = await pool.query(
    'SELECT * FROM hmrc_connections WHERE user_id = $1',
    [userId]
  );
  const conn = result.rows[0];
  if (!conn) throw new Error('HMRC account not connected');

  const thirtyMinsFromNow = new Date(Date.now() + 30 * 60 * 1000);
  if (conn.token_expires_at && new Date(conn.token_expires_at) > thirtyMinsFromNow) {
    // Token still valid — return it
    return decryptToken(conn.access_token);
  }

  // Token expired or expiring soon — refresh
  console.log(`[HMRC] Refreshing access token for user ${userId}`);
  const tokens = await hmrcRefreshTokens(conn.refresh_token);
  const newExpiry = new Date(Date.now() + (tokens.expires_in || 14400) * 1000);

  await pool.query(
    `UPDATE hmrc_connections
       SET access_token = $1, refresh_token = $2, token_expires_at = $3, updated_at = NOW()
       WHERE user_id = $4`,
    [encryptToken(tokens.access_token), encryptToken(tokens.refresh_token), newExpiry, userId]
  );

  try { logAuditEvent({ userId, eventType: 'hmrc_token_refreshed', entityType: 'hmrc_connection', entityId: userId }); } catch (_) {}
  return tokens.access_token;
}

// ─── OAuth: Initiate ──────────────────────────────────────
// GET /api/auth/hmrc?token=<JWT>[&vrn=<vrn>]
// Redirects user to HMRC Government Gateway authorization page
app.get('/api/auth/hmrc', authenticateTokenFromQuery, (req, res) => {
  if (!HMRC_CLIENT_ID) {
    return res.redirect('/dashboard?hmrc_error=HMRC+not+configured');
  }

  // Use HMRC_REDIRECT_URI if set, otherwise fall back to APP_URL or host header.
  // Must EXACTLY match what's registered in HMRC Developer Hub:
  // https://finowl.co.uk/api/auth/hmrc/callback
  const redirectUri = process.env.HMRC_REDIRECT_URI || process.env.APP_URL || `https://${req.headers.host}`;

  // Embed userId + VRN in signed state (expires in 10 min, CSRF-safe)
  const vrn = (req.query.vrn || '').replace(/^GB/i, '').replace(/\D/g, '');
  const state = jwt.sign(
    { userId: req.user.userId, vrn, nonce: crypto.randomBytes(8).toString('hex') },
    JWT_SECRET,
    { expiresIn: '10m' }
  );

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: HMRC_CLIENT_ID,
    scope: 'read:vat write:vat',
    redirect_uri: redirectUri,
    state,
  });

  const authorizeUrl = `https://${HMRC_API_HOST}/oauth/authorize?${params.toString()}`;
  res.redirect(authorizeUrl);
});

// ─── OAuth: Callback ──────────────────────────────────────
// GET /api/auth/hmrc/callback?code=...&state=...
app.get('/api/auth/hmrc/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    console.error('[HMRC] OAuth error:', error, error_description);
    return res.redirect(`/dashboard?hmrc_error=${encodeURIComponent(error_description || error)}`);
  }

  if (!code || !state) {
    return res.redirect('/dashboard?hmrc_error=missing+params');
  }

  let userId, vrn;
  try {
    const decoded = jwt.verify(state, JWT_SECRET);
    userId = decoded.userId;
    vrn = decoded.vrn || null;
  } catch {
    return res.redirect('/dashboard?hmrc_error=invalid+state');
  }

  try {
    const redirectUri = process.env.HMRC_REDIRECT_URI || process.env.APP_URL || `https://${req.headers.host}`;

    const tokens = await hmrcExchangeCode(code, redirectUri);
    const accessToken = tokens.access_token;
    const refreshToken = tokens.refresh_token;
    // HMRC access tokens are valid for 4 hours (14400 seconds)
    const expiresAt = new Date(Date.now() + (tokens.expires_in || 14400) * 1000);

    // Upsert into hmrc_connections (one connection per user)
    await pool.query(
      `INSERT INTO hmrc_connections
         (user_id, access_token, refresh_token, token_expires_at, vrn, connected_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
       ON CONFLICT (user_id) DO UPDATE
         SET access_token = EXCLUDED.access_token,
             refresh_token = EXCLUDED.refresh_token,
             token_expires_at = EXCLUDED.token_expires_at,
             vrn = COALESCE(EXCLUDED.vrn, hmrc_connections.vrn),
             updated_at = NOW()`,
      [userId, encryptToken(accessToken), encryptToken(refreshToken), expiresAt, vrn || null]
    );

    console.log(`[HMRC] Connected HMRC account for user ${userId}${vrn ? ` (VRN: ${vrn})` : ''}`);
    await logAudit({ userId, actionType: 'HMRC_CONNECTED', entityType: 'hmrc_connection', entityId: userId, newValue: { vrn: vrn || null, sandbox: HMRC_SANDBOX }, req });
    try { logAuditEvent({ userId, eventType: 'hmrc_connected', entityType: 'hmrc_connection', entityId: userId, details: { vrn: vrn || null } }); } catch (_) {}
    res.redirect('/dashboard?hmrc_connected=true');
  } catch (err) {
    console.error('[HMRC] Callback error:', err.message);
    res.redirect(`/dashboard?hmrc_error=${encodeURIComponent('Connection failed: ' + err.message)}`);
  }
});

// ─── HMRC Status ──────────────────────────────────────────
// GET /api/hmrc/status — returns connection status for current user
app.get('/api/hmrc/status', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT vrn, connected_at, token_expires_at FROM hmrc_connections WHERE user_id = $1',
      [req.user.userId]
    );
    if (!result.rows[0]) {
      return res.json({ connected: false });
    }
    const conn = result.rows[0];
    res.json({
      connected: true,
      vrn: conn.vrn,
      connected_at: conn.connected_at,
      token_expires_at: conn.token_expires_at,
      sandbox: HMRC_SANDBOX,
    });
  } catch (err) {
    console.error('[HMRC] Status error:', err.message);
    res.status(500).json({ error: 'Failed to fetch HMRC status' });
  }
});

// ─── HMRC Disconnect ─────────────────────────────────────
// DELETE /api/hmrc/disconnect — revoke and remove stored tokens
app.delete('/api/hmrc/disconnect', authenticateToken, requireOwner, async (req, res) => {
  try {
    await pool.query('DELETE FROM hmrc_connections WHERE user_id = $1', [req.user.userId]);
    try { logAuditEvent({ userId: req.user.userId, eventType: 'hmrc_disconnected', entityType: 'hmrc_connection', entityId: req.user.userId, details: null, req }); } catch (_) {}
    res.json({ success: true });
  } catch (err) {
    console.error('[HMRC] Disconnect error:', err.message);
    res.status(500).json({ error: 'Failed to disconnect HMRC' });
  }
});

// ─── HMRC Obligations ────────────────────────────────────
// GET /api/hmrc/obligations — fetch open VAT obligations from HMRC MTD API
app.get('/api/hmrc/obligations', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Get connection details
    const connResult = await pool.query(
      'SELECT vrn FROM hmrc_connections WHERE user_id = $1',
      [userId]
    );
    if (!connResult.rows[0]) {
      return res.status(400).json({ error: 'HMRC account not connected' });
    }
    const vrn = connResult.rows[0].vrn;
    if (!vrn) {
      return res.status(400).json({ error: 'VAT Registration Number not set — reconnect and enter your VRN' });
    }

    // Get valid (auto-refreshed) access token
    const accessToken = await getValidHmrcToken(userId);

    // Query last 12 months of obligations
    const fromDate = new Date(Date.now() - 366 * 24 * 60 * 60 * 1000).toISOString().substring(0, 10);
    const toDate = new Date().toISOString().substring(0, 10);

    // Build fraud prevention headers for obligations endpoint (HMRC required on ALL API calls)
    const clientUA = req.get('User-Agent') || '';
    let osStr = 'Unknown/Unknown';
    if (/Windows NT 10/.test(clientUA)) osStr = 'Windows/10';
    else if (/Windows NT 6\.3/.test(clientUA)) osStr = 'Windows/8.1';
    else if (/Windows NT 6\.1/.test(clientUA)) osStr = 'Windows/7';
    else if (/Mac OS X/.test(clientUA)) {
      const mv = clientUA.match(/Mac OS X ([\d_]+)/);
      osStr = `macOS/${mv ? mv[1].replace(/_/g, '.') : 'Unknown'}`;
    } else if (/Android/.test(clientUA)) {
      const av = clientUA.match(/Android ([\d.]+)/);
      osStr = `Android/${av ? av[1] : 'Unknown'}`;
    } else if (/iPhone|iPad/.test(clientUA)) {
      const iv = clientUA.match(/OS ([\d_]+)/);
      osStr = `iOS/${iv ? iv[1].replace(/_/g, '.') : 'Unknown'}`;
    } else if (/Linux/.test(clientUA)) osStr = 'Linux/Unknown';

    const clientPublicIP = req.ip || req.connection?.remoteAddress || '';
    const vendorPublicIP = process.env.GOV_VENDOR_PUBLIC_IP || req.socket?.localAddress || '0.0.0.0';

    const fraudHeaders = {
      'Gov-Client-Connection-Method': 'WEB_APP_VIA_SERVER',
      'Gov-Client-User-Agent': osStr,
      'Gov-Client-Public-IP': clientPublicIP,
      'Gov-Client-Local-IPs': clientPublicIP,
      'Gov-Client-Screens': '1920x1080',
      'Gov-Client-Window-Size': '1280x800',
      'Gov-Client-Browser-JS-User-Agent': clientUA,
      'Gov-Client-Browser-Do-Not-Track': 'false',
      'Gov-Vendor-Version': 'FinOwl-V1.0.0',
      'Gov-Vendor-Public-IP': vendorPublicIP,
    };

    const apiRes = await hmrcRequest(
      HMRC_API_HOST,
      `/organisations/vat/${vrn}/obligations?from=${fromDate}&to=${toDate}&status=O`,
      'GET',
      {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/vnd.hmrc.1.0+json',
        ...fraudHeaders,
      }
    );

    if (apiRes.status === 404) {
      // No obligations found (sandbox may return this for test users)
      return res.json({ obligations: [] });
    }
    if (apiRes.status !== 200) {
      console.error('[HMRC] Obligations API error:', apiRes.status, apiRes.body);
      return res.status(502).json({
        error: 'HMRC API error',
        details: apiRes.body?.message || apiRes.body,
      });
    }

    res.json({ obligations: apiRes.body.obligations || [] });
  } catch (err) {
    console.error('[HMRC] Obligations error:', err.message);
    if (err.message.includes('not connected')) {
      return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Failed to fetch obligations', details: err.message });
  }
});

// ─── VAT Submissions History ──────────────────────────────
// HMRC Test Fraud Prevention Headers Validation endpoint
// POST /api/hmrc/test-fraud-headers
app.post('/api/hmrc/test-fraud-headers', authenticateToken, async (req, res) => {
  try {
    const uid = req.user.userId;
    const { deviceData } = req.body || {};
    const dd = deviceData || {};
    const cUA = dd.userAgent || req.get('User-Agent') || '';
    const cScreens = dd.screenResolution || '1920x1080';
    const cWindow = dd.windowSize || '1280x800';
    const cDNT = (dd.doNotTrack === true || dd.doNotTrack === 'true') ? 'true' : 'false';
    const cLocalIPs = dd.localIPs || '';
    const cPublicIP = dd.publicIP || req.ip || req.connection?.remoteAddress || '';
    const vPublicIP = process.env.GOV_VENDOR_PUBLIC_IP || req.socket?.localAddress || '0.0.0.0';
    let osStr = 'Unknown/Unknown';
    if (/Windows NT 10/.test(cUA)) osStr = 'Windows/10';
    else if (/Windows NT 6\.3/.test(cUA)) osStr = 'Windows/8.1';
    else if (/Windows NT 6\.1/.test(cUA)) osStr = 'Windows/7';
    else if (/Mac OS X/.test(cUA)) { const mv = cUA.match(/Mac OS X ([\d_]+)/); osStr = 'macOS/' + (mv ? mv[1].replace(/_/g, '.') : 'Unknown'); }
    else if (/Android/.test(cUA)) { const av = cUA.match(/Android ([\d.]+)/); osStr = 'Android/' + (av ? av[1] : 'Unknown'); }
    else if (/iPhone|iPad/.test(cUA)) { const iv = cUA.match(/OS ([\d_]+)/); osStr = 'iOS/' + (iv ? iv[1].replace(/_/g, '.') : 'Unknown'); }
    else if (/Linux/.test(cUA)) osStr = 'Linux/Unknown';
    const fraudHeaders = {
      'Gov-Client-Connection-Method': 'WEB_APP_VIA_SERVER',
      'Gov-Client-User-Agent': osStr,
      'Gov-Client-Public-IP': cPublicIP,
      'Gov-Client-Local-IPs': cLocalIPs || cPublicIP,
      'Gov-Client-Screens': cScreens,
      'Gov-Client-Window-Size': cWindow,
      'Gov-Client-Browser-JS-User-Agent': cUA,
      'Gov-Client-Browser-Do-Not-Track': cDNT,
      'Gov-Vendor-Version': 'FinOwl-V1.0.0',
      'Gov-Vendor-Public-IP': vPublicIP,
    };
    console.log('[HMRC] Testing fraud prevention headers for user ' + uid);
    const apiRes = await hmrcRequest(HMRC_API_HOST, '/test/fraud-prevention-headers/validate', 'POST', {
      'Accept': 'application/vnd.hmrc.1.0+json',
      'Content-Type': 'application/json',
      ...fraudHeaders,
    }, JSON.stringify({}));
    const result = { valid: apiRes.status === 200, status: apiRes.status, headers: fraudHeaders, response: apiRes.body, sandbox: HMRC_SANDBOX };
    if (apiRes.status === 200) {
      console.log('[HMRC] Fraud prevention headers VALID for user ' + uid);
      res.json(result);
    } else {
      console.error('[HMRC] Fraud prevention headers INVALID: ' + apiRes.status, JSON.stringify(apiRes.body));
      res.status(apiRes.status).json(result);
    }
  } catch (err) {
    console.error('[HMRC] Test fraud headers error:', err.message);
    res.status(500).json({ error: 'Failed to validate fraud prevention headers', details: err.message });
  }
});

// GET /api/vat/submissions — list all VAT returns filed by this user
app.get('/api/vat/submissions', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, quarter, period_key, period_start, period_end, box5,
              status, hmrc_processing_date, hmrc_form_bundle_number,
              submitted_at, created_at
         FROM vat_submissions
         WHERE user_id = $1
         ORDER BY period_start DESC
         LIMIT 20`,
      [req.user.userId]
    );
    res.json({ submissions: result.rows });
  } catch (err) {
    console.error('[VAT] Submissions error:', err.message);
    res.status(500).json({ error: 'Failed to fetch submissions' });
  }
});

// ─── VAT Submit to HMRC MTD ──────────────────────────────
// POST /api/vat/submit — submit a real VAT return to HMRC sandbox (Phase 1b)
// Body: { quarter, periodKey, deviceData: { userAgent, screenResolution, windowSize, doNotTrack, localIPs, publicIP } }
app.post('/api/vat/submit', authenticateToken, requireOwner, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { quarter, periodKey, deviceData } = req.body;

    if (!periodKey) return res.status(400).json({ error: 'periodKey is required (select from HMRC obligations)' });
    if (!quarter) return res.status(400).json({ error: 'quarter is required (e.g. Q1-2026)' });

    // 1. Get VRN and validate connection
    const connResult = await pool.query(
      'SELECT vrn FROM hmrc_connections WHERE user_id = $1',
      [userId]
    );
    if (!connResult.rows[0]) return res.status(400).json({ error: 'HMRC account not connected' });
    const vrn = connResult.rows[0].vrn;
    if (!vrn) return res.status(400).json({ error: 'VRN not set — reconnect and enter your VRN' });

    // 2. Get valid (auto-refreshed) access token
    const accessToken = await getValidHmrcToken(userId);

    // 3. Calculate VAT boxes for the quarter (same logic as /api/vat/summary)
    const match = quarter.match(/^Q([1-4])-(\d{4})$/);
    if (!match) return res.status(400).json({ error: 'Invalid quarter format. Use Q1-2026, Q2-2026, etc.' });
    const q = parseInt(match[1]);
    const year = parseInt(match[2]);
    const quarterMonths = {
      1: { start: `${year}-01-01`, end: `${year}-03-31` },
      2: { start: `${year}-04-01`, end: `${year}-06-30` },
      3: { start: `${year}-07-01`, end: `${year}-09-30` },
      4: { start: `${year}-10-01`, end: `${year}-12-31` },
    };
    const { start: startDate, end: endDate } = quarterMonths[q];

    const vatResult = await pool.query(`
      SELECT t.amount, c.is_income, c.vat_rate
      FROM transactions t
      JOIN categories c ON t.category_id = c.id
      WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3 AND c.vat_rate IS NOT NULL
    `, [userId, startDate, endDate]);

    const allResult = await pool.query(`
      SELECT t.amount, COALESCE(c.is_income, CASE WHEN t.amount > 0 THEN true ELSE false END) as is_income
      FROM transactions t
      LEFT JOIN categories c ON t.category_id = c.id
      WHERE t.user_id = $1 AND t.date >= $2 AND t.date <= $3
    `, [userId, startDate, endDate]);

    let outputVat = 0;
    let inputVat = 0;
    for (const row of vatResult.rows) {
      const gross = Math.abs(parseFloat(row.amount));
      const rate = parseFloat(row.vat_rate);
      const vatAmount = gross - (gross / (1 + rate / 100));
      if (row.is_income) outputVat += vatAmount;
      else inputVat += vatAmount;
    }

    let totalSalesGross = 0;
    let totalPurchasesGross = 0;
    for (const row of allResult.rows) {
      if (row.is_income) totalSalesGross += Math.abs(parseFloat(row.amount));
      else totalPurchasesGross += Math.abs(parseFloat(row.amount));
    }

    // HMRC payload boxes (boxes 1-5 are decimals, 6-9 are integers per MTD spec)
    const vatDueSales = parseFloat(Math.max(0, outputVat).toFixed(2));
    const vatDueAcquisitions = 0.00;                                          // Box 2: post-Brexit = 0
    const totalVatDue = parseFloat((vatDueSales + vatDueAcquisitions).toFixed(2)); // Box 3 = Box 1 + Box 2
    const vatReclaimedCurrPeriod = parseFloat(Math.max(0, inputVat).toFixed(2));  // Box 4
    const netVatDue = Math.round(Math.abs(totalVatDue - vatReclaimedCurrPeriod)); // Box 5: whole £ only
    const totalValueSalesExVAT = Math.round(Math.max(0, totalSalesGross - outputVat));     // Box 6: whole £
    const totalValuePurchasesExVAT = Math.round(Math.max(0, totalPurchasesGross - inputVat)); // Box 7: whole £
    const totalValueGoodsSuppliedExVAT = 0;                                   // Box 8
    const totalAcquisitionsExVAT = 0;                                         // Box 9

    // 4. Build fraud prevention headers (HMRC mandatory for all API calls)
    const dd = deviceData || {};
    const clientUserAgent = dd.userAgent || req.get('User-Agent') || '';
    const clientScreens = dd.screenResolution || '1920x1080';
    const clientWindowSize = dd.windowSize || '1280x800';
    const clientDoNotTrack = (dd.doNotTrack === true || dd.doNotTrack === 'true') ? 'true' : 'false';
    const clientLocalIPs = dd.localIPs || '';
    const clientPublicIP = dd.publicIP || req.ip || req.connection?.remoteAddress || '';
    const vendorPublicIP = process.env.GOV_VENDOR_PUBLIC_IP || req.socket?.localAddress || '0.0.0.0';

    // Derive OS family string from User-Agent
    const ua = clientUserAgent;
    let osStr = 'Unknown/Unknown';
    if (/Windows NT 10/.test(ua)) osStr = 'Windows/10';
    else if (/Windows NT 6\.3/.test(ua)) osStr = 'Windows/8.1';
    else if (/Windows NT 6\.1/.test(ua)) osStr = 'Windows/7';
    else if (/Mac OS X/.test(ua)) {
      const mv = ua.match(/Mac OS X ([\d_]+)/);
      osStr = `macOS/${mv ? mv[1].replace(/_/g, '.') : 'Unknown'}`;
    } else if (/Android/.test(ua)) {
      const av = ua.match(/Android ([\d.]+)/);
      osStr = `Android/${av ? av[1] : 'Unknown'}`;
    } else if (/iPhone|iPad/.test(ua)) {
      const iv = ua.match(/OS ([\d_]+)/);
      osStr = `iOS/${iv ? iv[1].replace(/_/g, '.') : 'Unknown'}`;
    } else if (/Linux/.test(ua)) {
      osStr = 'Linux/Unknown';
    }

    const fraudHeaders = {
      'Gov-Client-Connection-Method': 'WEB_APP_VIA_SERVER',
      'Gov-Client-User-Agent': osStr,
      'Gov-Client-Public-IP': clientPublicIP,
      'Gov-Client-Local-IPs': clientLocalIPs || clientPublicIP,
      'Gov-Client-Screens': clientScreens,
      'Gov-Client-Window-Size': clientWindowSize,
      'Gov-Client-Browser-JS-User-Agent': clientUserAgent,
      'Gov-Client-Browser-Do-Not-Track': clientDoNotTrack,
      'Gov-Vendor-Version': 'FinOwl-V1.0.0',
      'Gov-Vendor-Public-IP': vendorPublicIP,
    };

    // 5. Build HMRC JSON payload
    const hmrcPayload = JSON.stringify({
      periodKey,
      vatDueSales,
      vatDueAcquisitions,
      totalVatDue,
      vatReclaimedCurrPeriod,
      netVatDue,
      totalValueSalesExVAT,
      totalValuePurchasesExVAT,
      totalValueGoodsSuppliedExVAT,
      totalAcquisitionsExVAT,
      finalised: true,
    });

    console.log(`[HMRC] Submitting VAT return: user=${userId} VRN=${vrn} period=${periodKey} quarter=${quarter} sandbox=${HMRC_SANDBOX}`);

    // 6. POST to HMRC MTD API
    const hmrcRes = await hmrcRequest(
      HMRC_API_HOST,
      `/organisations/vat/${vrn}/returns`,
      'POST',
      {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/vnd.hmrc.1.0+json',
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(hmrcPayload),
        ...fraudHeaders,
      },
      hmrcPayload
    );

    // 7. Handle HMRC API errors with specific, user-friendly messages
    if (hmrcRes.status !== 200 && hmrcRes.status !== 201 && hmrcRes.status !== 202) {
      console.error('[HMRC] Submission rejected:', hmrcRes.status, JSON.stringify(hmrcRes.body));
      const errCode = hmrcRes.body?.code || hmrcRes.body?.errors?.[0]?.code || '';
      const errDetails = hmrcRes.body?.message || JSON.stringify(hmrcRes.body);

      // Map known HMRC error codes to clear user messages
      const userMessage = (() => {
        switch (errCode) {
          case 'DUPLICATE_SUBMISSION':
            return 'A VAT return for this period has already been submitted. Check your filing history.';
          case 'INVALID_MONETARY_AMOUNT':
            return 'One or more VAT box values are invalid. Boxes 6–9 must be whole pounds (no pence). Please check your data and try again.';
          case 'BUSINESS_ERROR':
            return 'HMRC rejected the return due to a calculation error. Verify: Box 3 = Box 1 + Box 2, Box 5 = |Box 3 − Box 4|.';
          case 'INVALID_REQUEST':
          case 'MANDATORY_FIELD_MISSING':
            return 'The VAT return payload was rejected by HMRC. Contact support if this persists.';
          case 'INVALID_FRAUD_HEADERS':
            return 'HMRC fraud prevention headers were rejected. Please reload the page and try again.';
          case 'PERIOD_KEY_INVALID':
            return 'The selected obligation period is no longer valid. Reload the page to refresh your obligations.';
          default:
            return `HMRC rejected this submission (${errCode || hmrcRes.status})`;
        }
      })();

      await pool.query(
        `INSERT INTO vat_submissions
           (user_id, quarter, period_key, period_start, period_end,
            box1, box2, box3, box4, box5, box6, box7, box8, box9,
            status, error_message, finalised, hmrc_response)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                 'error',$15,false,$16::jsonb)`,
        [userId, quarter, periodKey, startDate, endDate,
         vatDueSales, vatDueAcquisitions, totalVatDue, vatReclaimedCurrPeriod, netVatDue,
         totalValueSalesExVAT, totalValuePurchasesExVAT, totalValueGoodsSuppliedExVAT, totalAcquisitionsExVAT,
         errDetails.substring(0, 500),
         JSON.stringify(hmrcRes.body)]
      );
      await logAudit({ userId, actionType: 'VAT_SUBMIT_FAILED', entityType: 'vat_submission', entityId: null, newValue: { quarter, periodKey, errCode, status: hmrcRes.status }, req });
      return res.status(502).json({ error: userMessage, details: errDetails, code: errCode });
    }

    // 8. Parse HMRC receipt — supports both v1.0 body fields (formBundleNumber) and header-based Receipt-ID
    const receipt = (typeof hmrcRes.body === 'object' ? hmrcRes.body : {});
    const resHeaders = hmrcRes.headers || {};
    // HMRC v1.0: formBundleNumber is the primary receipt identifier; header Receipt-ID is v2+
    const receiptId = receipt.formBundleNumber || receipt['receipt-id'] || resHeaders['receipt-id'] || receipt.receiptId || '';
    const receiptTimestamp = receipt.processingDate || receipt['receipt-timestamp'] || resHeaders['receipt-timestamp'] || new Date().toISOString();
    const paymentIndicator = receipt.paymentIndicator || '';
    const chargeRefNumber = receipt.chargeRefNumber || '';

    // 9. Persist to vat_submissions
    await pool.query(
      `INSERT INTO vat_submissions
         (user_id, quarter, period_key, period_start, period_end,
          box1, box2, box3, box4, box5, box6, box7, box8, box9,
          status, hmrc_form_bundle_number, hmrc_processing_date, hmrc_payment_indicator,
          hmrc_charge_ref_number, hmrc_response, finalised, submitted_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
               'submitted',$15,$16,$17,$18,$19::jsonb,true,NOW())
       ON CONFLICT DO NOTHING`,
      [userId, quarter, periodKey, startDate, endDate,
       vatDueSales, vatDueAcquisitions, totalVatDue, vatReclaimedCurrPeriod, netVatDue,
       totalValueSalesExVAT, totalValuePurchasesExVAT, totalValueGoodsSuppliedExVAT, totalAcquisitionsExVAT,
       receiptId, receiptTimestamp, paymentIndicator, chargeRefNumber, JSON.stringify(receipt)]
    );

    console.log(`[HMRC] VAT return submitted. formBundleNumber=${receiptId || '(sandbox)'} periodKey=${periodKey}`);
    await logAudit({ userId, actionType: 'VAT_SUBMITTED', entityType: 'vat_submission', entityId: null, newValue: { quarter, periodKey, receiptId, receiptTimestamp, sandbox: HMRC_SANDBOX }, req });
    logAuditEvent({
      userId,
      eventType: 'vat_submitted',
      entityType: 'vat_return',
      entityId: null,
      details: { quarter, period_key: periodKey, receipt_id: receiptId, receipt_timestamp: receiptTimestamp, sandbox: HMRC_SANDBOX },
      req,
    });

    res.json({
      success: true,
      receiptId,
      receiptTimestamp,
      paymentIndicator,
      periodKey,
      quarter,
      sandbox: HMRC_SANDBOX,
    });
  } catch (err) {
    console.error('[HMRC] Submit error:', err.message);
    if (err.message.includes('not connected')) {
      return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Failed to submit VAT return', details: err.message });
  }
});

// ─── Chat Widget API ─────────────────────────────────────
// Pre-sales AI assistant for the landing page (no auth required)

// Simple in-memory rate limiter: 20 requests per IP per minute
const _chatRateLimits = new Map();
const _CHAT_RATE_LIMIT = 20;
const _CHAT_RATE_WINDOW = 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of _chatRateLimits.entries()) {
    if (now - entry.window > _CHAT_RATE_WINDOW * 2) _chatRateLimits.delete(ip);
  }
}, 5 * 60 * 1000);

function _chatRateLimit(req, res, next) {
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const now = Date.now();
  const entry = _chatRateLimits.get(ip);
  if (!entry || now - entry.window > _CHAT_RATE_WINDOW) {
    _chatRateLimits.set(ip, { count: 1, window: now });
    return next();
  }
  if (entry.count >= _CHAT_RATE_LIMIT) {
    return res.status(429).json({ error: 'Too many requests. Please wait a moment.' });
  }
  entry.count++;
  next();
}

const _FINOWL_SYSTEM_PROMPT = `You are FinOwl's friendly pre-sales assistant. You help UK sole traders understand FinOwl before subscribing.

Key facts about FinOwl:
- Price: £59/month. No setup fees. Cancel any time.
- Who it's for: UK sole traders only. Limited company support is coming soon.
- MTD compliant: fully ready for HMRC Making Tax Digital for VAT. Income Tax MTD support from April 2026.
- Bank connectivity: Open Banking via TrueLayer (read-only). Works with Starling, Monzo, Barclays, HSBC, Lloyds, NatWest, Santander, and 50+ UK banks.
- AI categorisation: automatically sorts transactions into 15 UK business categories. You can correct mistakes and it learns your rules.
- VAT: real-time VAT liability tracking, quarterly VAT summary, ready to submit to HMRC.
- Tax: live P&L, income/expense tracking, year-end summaries, tax liability estimates.
- Security: 256-bit encryption at rest and in transit. GDPR compliant. UK servers. Open Banking is read-only — FinOwl can NEVER move your money.
- Accountant access: give your accountant read-only access to your dashboard, or export CSV/PDF.
- Manual work: minimal. Connect your bank, occasionally review categorisations, submit VAT returns.
- What it doesn't do: payroll, corporation tax, PAYE, pension management.
- Legal: FinOwl is not a substitute for a licensed accountant or tax advisor.
- Contact: finowl@polsia.app (24-hour response).

Answer concisely (under 150 words unless detail is genuinely needed). Be honest about limitations. If unsure, suggest emailing finowl@polsia.app.`;

app.post('/api/chat/presales', _chatRateLimit, async (req, res) => {
  try {
    const { message, history = [] } = req.body;
    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return res.status(400).json({ error: 'Message is required' });
    }
    if (message.trim().length > 500) {
      return res.status(400).json({ error: 'Message too long (max 500 characters)' });
    }

    const safeHistory = Array.isArray(history)
      ? history.slice(-6).filter(h => h && (h.role === 'user' || h.role === 'assistant') && typeof h.content === 'string')
      : [];

    const messages = [
      { role: 'system', content: _FINOWL_SYSTEM_PROMPT },
      ...safeHistory.map(h => ({ role: h.role, content: h.content })),
      { role: 'user', content: message.trim() },
    ];

    const response = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages,
      max_tokens: 300,
      temperature: 0.7,
    });

    const reply = response.choices[0]?.message?.content || 'Sorry, I could not generate a response. Please email finowl@polsia.app.';
    res.json({ reply });
  } catch (err) {
    console.error('[Chat] Error:', err.message);
    if (err.status === 429) {
      return res.status(429).json({ error: 'AI service is busy. Please try again in a moment.' });
    }
    res.status(500).json({ error: 'Something went wrong. Please email finowl@polsia.app for help.' });
  }
});

// ═══════════════════════════════════════════════════════════
// DUPLICATE DETECTION API
// ═══════════════════════════════════════════════════════════

// GET /api/transactions/duplicates
// On-demand full scan of the last 90 days; upserts new pairs then returns all
// pending duplicate_pairs with full transaction details for the review modal.
app.get('/api/transactions/duplicates', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Full scan: fetch all non-duplicate transactions from the last 90 days
    const txRes = await pool.query(
      `SELECT id, date, amount, description, merchant_name
       FROM transactions
       WHERE user_id = $1
         AND date >= NOW() - INTERVAL '90 days'
         AND (is_duplicate IS NULL OR is_duplicate = false)
       ORDER BY date DESC, id DESC`,
      [userId]
    );
    const txns = txRes.rows;

    // O(n²) comparison — bounded by 90-day window (typically < 500 transactions)
    for (let i = 0; i < txns.length; i++) {
      for (let j = i + 1; j < txns.length; j++) {
        const a = txns[i];
        const b = txns[j];
        if (Math.abs(parseFloat(a.amount) - parseFloat(b.amount)) >= 0.01) continue;

        const daysDiff    = Math.abs(new Date(a.date) - new Date(b.date)) / 86400000;
        if (daysDiff > 1) continue;

        const dateScore   = Math.max(0, 1 - daysDiff);
        const vendorScore = vendorSimilarity(
          a.merchant_name || a.description || '',
          b.merchant_name || b.description || ''
        );
        const confidence = Math.round((0.4 + 0.3 * dateScore + 0.3 * vendorScore) * 1000) / 1000;
        if (confidence >= 0.7) {
          const id1 = Math.min(a.id, b.id);
          const id2 = Math.max(a.id, b.id);
          await pool.query(
            `INSERT INTO duplicate_pairs
               (user_id, transaction_id_1, transaction_id_2, match_reason, match_score, status)
             VALUES ($1, $2, $3, 'fuzzy_match', $4, 'pending')
             ON CONFLICT (transaction_id_1, transaction_id_2) DO NOTHING`,
            [userId, id1, id2, confidence]
          );
        }
      }
    }

    // Return all pending pairs with full transaction details
    const pairsRes = await pool.query(
      `SELECT
         dp.id             AS pair_id,
         dp.match_score,
         dp.match_reason,
         t1.id             AS tx1_id,
         t1.date           AS tx1_date,
         t1.amount         AS tx1_amount,
         t1.description    AS tx1_description,
         t1.merchant_name  AS tx1_merchant,
         t1.reference      AS tx1_reference,
         bc1.display_name  AS tx1_bank,
         t2.id             AS tx2_id,
         t2.date           AS tx2_date,
         t2.amount         AS tx2_amount,
         t2.description    AS tx2_description,
         t2.merchant_name  AS tx2_merchant,
         t2.reference      AS tx2_reference,
         bc2.display_name  AS tx2_bank
       FROM duplicate_pairs dp
       JOIN transactions t1 ON dp.transaction_id_1 = t1.id
       JOIN transactions t2 ON dp.transaction_id_2 = t2.id
       LEFT JOIN bank_connections bc1 ON t1.bank_connection_id = bc1.id
       LEFT JOIN bank_connections bc2 ON t2.bank_connection_id = bc2.id
       WHERE dp.user_id = $1 AND dp.status = 'pending'
       ORDER BY dp.match_score DESC, dp.created_at DESC`,
      [userId]
    );

    res.json({ pairs: pairsRes.rows, total: pairsRes.rows.length });
  } catch (err) {
    console.error('GET /api/transactions/duplicates error:', err);
    res.status(500).json({ error: 'Failed to scan for duplicates' });
  }
});

// POST /api/transactions/merge
// Soft-deletes remove_ids (is_duplicate=true) while preserving the kept transaction.
// Preserves category and receipt links from removed transaction if kept lacks them.
app.post('/api/transactions/merge', authenticateToken, requireOwner, async (req, res) => {
  try {
    const { keep_id, remove_ids } = req.body;
    const userId = req.user.userId;

    if (!keep_id || !Array.isArray(remove_ids) || !remove_ids.length) {
      return res.status(400).json({ error: 'keep_id and remove_ids[] are required' });
    }

    // Verify keep_id belongs to this user
    const keepRes = await pool.query(
      `SELECT id, category_id, notes FROM transactions WHERE id = $1 AND user_id = $2`,
      [keep_id, userId]
    );
    if (!keepRes.rows.length) return res.status(404).json({ error: 'Transaction not found' });
    const keepTx = keepRes.rows[0];

    for (const removeId of remove_ids) {
      const removeRes = await pool.query(
        `SELECT id, category_id, notes FROM transactions WHERE id = $1 AND user_id = $2`,
        [removeId, userId]
      );
      if (!removeRes.rows.length) continue;
      const removeTx = removeRes.rows[0];

      // Preserve category from removed tx if kept tx has none
      if (!keepTx.category_id && removeTx.category_id) {
        await pool.query(
          `UPDATE transactions SET category_id = $1 WHERE id = $2`,
          [removeTx.category_id, keep_id]
        );
        keepTx.category_id = removeTx.category_id;
      }

      // Re-link receipts from removed tx to kept tx
      await pool.query(
        `UPDATE receipts SET matched_transaction_id = $1
         WHERE matched_transaction_id = $2 AND user_id = $3`,
        [keep_id, removeId, userId]
      );

      // Soft-delete the removed transaction
      await pool.query(
        `UPDATE transactions
         SET is_duplicate = true, duplicate_of = $1, updated_at = NOW()
         WHERE id = $2 AND user_id = $3`,
        [keep_id, removeId, userId]
      );

      // Resolve the duplicate_pair record
      await pool.query(
        `UPDATE duplicate_pairs
         SET status = 'merged', resolved_at = NOW()
         WHERE user_id = $1 AND (
           (transaction_id_1 = $2 AND transaction_id_2 = $3) OR
           (transaction_id_1 = $3 AND transaction_id_2 = $2)
         )`,
        [userId, keep_id, removeId]
      );
    }

    // Audit trail (fire-and-forget)
    try {
      await logAuditEvent({ userId, eventType: 'duplicate_merged', entityType: 'transaction', entityId: keep_id, details: { removed_ids: remove_ids } });
    } catch (_) {}

    res.json({ success: true, kept_id: keep_id, removed_ids: remove_ids });
  } catch (err) {
    console.error('POST /api/transactions/merge error:', err);
    res.status(500).json({ error: 'Failed to merge transactions' });
  }
});

// POST /api/transactions/duplicates/:pairId/dismiss
// User confirms transactions are NOT duplicates — marks pair as 'kept_both'.
app.post('/api/transactions/duplicates/:pairId/dismiss', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const pairId = parseInt(req.params.pairId);
    await pool.query(
      `UPDATE duplicate_pairs SET status = 'kept_both', resolved_at = NOW()
       WHERE id = $1 AND user_id = $2`,
      [pairId, userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Dismiss duplicate pair error:', err);
    res.status(500).json({ error: 'Failed to dismiss pair' });
  }
});

// ─── HMRC Activity Log ─────────────────────────────────
// GET /api/audit-log?page=1&limit=50&entity_type=invoice&event_type=hmrc_connected&start_date=2025-01-01&end_date=2025-12-31
// Paginated, auth-required. Reads from audit_events (HMRC compliance log).
// Filters: entity_type, event_type, start_date, end_date
app.get('/api/audit-log', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const page     = Math.max(1, parseInt(req.query.page)     || 1);
    const limit    = Math.min(100, Math.max(1, parseInt(req.query.limit) || 50));
    const offset   = (page - 1) * limit;
    const entityType = req.query.entity_type || null;
    const eventType   = req.query.event_type   || null;
    const startDate   = req.query.start_date   || null;
    const endDate     = req.query.end_date     || null;

    const params = [userId];
    let where = 'WHERE user_id = $1';

    if (entityType) {
      params.push(entityType);
      where += ` AND entity_type = $${params.length}`;
    }
    if (eventType) {
      params.push(eventType);
      where += ` AND event_type = $${params.length}`;
    }
    if (startDate) {
      params.push(startDate);
      where += ` AND created_at >= $${params.length}::date`;
    }
    if (endDate) {
      params.push(endDate + 'T23:59:59.999Z');
      where += ` AND created_at <= $${params.length}::timestamptz`;
    }

    const countRes = await pool.query(
      `SELECT COUNT(*) AS total FROM audit_events ${where}`,
      params
    );
    const total = parseInt(countRes.rows[0].total);
    const pages = Math.ceil(total / limit);

    params.push(limit, offset);
    const eventsRes = await pool.query(
      `SELECT id, event_type, entity_type, entity_id, details, ip_address, created_at
       FROM audit_events ${where}
       ORDER BY created_at DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    res.json({ events: eventsRes.rows, total, page, pages });
  } catch (err) {
    console.error('GET /api/audit-log error:', err);
    res.status(500).json({ error: 'Failed to load activity log' });
  }
});

// ═══════════════════════════════════════════════════════════
// RECURRING INVOICES
// ═══════════════════════════════════════════════════════════

// ─── Helper: advance date by frequency ───────────────────
function advanceByFrequency(date, frequency) {
  const d = new Date(date);
  switch (frequency) {
    case 'weekly':    d.setDate(d.getDate() + 7);         break;
    case 'monthly':   d.setMonth(d.getMonth() + 1);       break;
    case 'quarterly': d.setMonth(d.getMonth() + 3);       break;
    case 'yearly':    d.setFullYear(d.getFullYear() + 1); break;
  }
  return d.toISOString().slice(0, 10);
}

// ─── Helper: build invoice email HTML ────────────────────
function buildInvoiceEmailHtml({ invoice, items, profile }) {
  const baseUrl = process.env.APP_URL || 'https://finowl.co.uk';
  const viewLink = `${baseUrl}/i/${invoice.view_token}`;
  const pdfLink  = `${baseUrl}/api/invoices/p/${invoice.view_token}/pdf`;
  const bizName  = (profile && profile.business_name) ? profile.business_name : 'Your service provider';
  const fmtGBP  = (n) => `£${parseFloat(n || 0).toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  const fmtDate = (d) => d ? new Date(d).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }) : '—';

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { background:#f5f4f1; font-family:'Helvetica Neue',Arial,sans-serif; color:#0a0f1a; }
    .wrap { max-width:580px; margin:32px auto; }
    .header { background:#0a0f1a; border-radius:12px 12px 0 0; padding:20px 28px; display:flex; align-items:center; gap:10px; }
    .header-owl { background:#d4920b; border-radius:50%; width:34px; height:34px; display:inline-flex; align-items:center; justify-content:center; font-size:16px; }
    .header-name { color:#fff; font-size:18px; font-weight:700; letter-spacing:-0.3px; }
    .body { background:#fff; padding:28px; border-radius:0 0 12px 12px; border:1px solid #e5e2db; border-top:none; }
    h2 { font-size:20px; font-weight:700; margin-bottom:6px; }
    p.sub { color:#6b7280; font-size:14px; margin-bottom:20px; line-height:1.6; }
    .inv-box { background:#f9f8f6; border:1px solid #e5e2db; border-radius:10px; padding:18px 20px; margin:20px 0; }
    .inv-row { display:flex; justify-content:space-between; padding:7px 0; font-size:14px; border-bottom:1px solid #f0eee9; }
    .inv-row:last-child { border-bottom:none; }
    .inv-label { color:#6b7280; }
    .inv-total { font-size:16px; font-weight:700; color:#0a0f1a; padding-top:10px; }
    .btn { display:inline-block; background:#d4920b; color:#fff; text-decoration:none; padding:13px 26px; border-radius:8px; font-weight:600; font-size:14px; margin-top:16px; margin-right:10px; }
    .btn-outline { background:#fff; color:#0a0f1a; border:1.5px solid #e5e2db; }
    .divider { height:1px; background:#e5e2db; margin:20px 0; }
    .footer { margin-top:20px; text-align:center; font-size:12px; color:#9ca3af; }
    .footer a { color:#d4920b; text-decoration:none; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <span class="header-owl">🦉</span>
      <span class="header-name">${bizName}</span>
    </div>
    <div class="body">
      <h2>Invoice ${invoice.invoice_number}</h2>
      <p class="sub">Please find your invoice details below. Payment is due by ${fmtDate(invoice.due_date)}.</p>
      <div class="inv-box">
        <div class="inv-row"><span class="inv-label">Invoice No.</span><span>${invoice.invoice_number}</span></div>
        <div class="inv-row"><span class="inv-label">Issue Date</span><span>${fmtDate(invoice.issue_date)}</span></div>
        <div class="inv-row"><span class="inv-label">Due Date</span><span>${fmtDate(invoice.due_date)}</span></div>
        ${parseFloat(invoice.vat_rate) > 0 ? `
        <div class="inv-row"><span class="inv-label">Subtotal</span><span>${fmtGBP(invoice.subtotal)}</span></div>
        <div class="inv-row"><span class="inv-label">VAT (${invoice.vat_rate}%)</span><span>${fmtGBP(invoice.vat_amount)}</span></div>` : ''}
        <div class="inv-row inv-total"><span>Total Due</span><span>${fmtGBP(invoice.total)}</span></div>
      </div>
      ${profile && profile.bank_sort_code ? `
      <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:14px 16px;margin:16px 0;font-size:14px">
        <div style="font-weight:600;color:#166534;margin-bottom:8px">💳 Payment Details</div>
        ${profile.bank_name ? `<div style="display:flex;gap:8px;margin-bottom:4px"><span style="color:#6b7280;min-width:120px">Bank</span><span>${profile.bank_name}</span></div>` : ''}
        ${profile.bank_sort_code ? `<div style="display:flex;gap:8px;margin-bottom:4px"><span style="color:#6b7280;min-width:120px">Sort Code</span><span>${profile.bank_sort_code}</span></div>` : ''}
        ${profile.bank_account_number ? `<div style="display:flex;gap:8px;margin-bottom:4px"><span style="color:#6b7280;min-width:120px">Account No.</span><span>${profile.bank_account_number}</span></div>` : ''}
        ${profile.bank_reference ? `<div style="display:flex;gap:8px"><span style="color:#6b7280;min-width:120px">Reference</span><span>${profile.bank_reference || invoice.invoice_number}</span></div>` : ''}
      </div>` : ''}
      ${invoice.notes ? `<div style="background:#fff8e6;border:1px solid #f5dfa3;border-radius:8px;padding:14px 16px;margin:16px 0;font-size:14px;color:#6b7280">${invoice.notes}</div>` : ''}
      <div style="margin-top:20px">
        <a href="${viewLink}" class="btn">View Invoice Online</a>
        <a href="${pdfLink}" class="btn btn-outline">⬇ Download PDF</a>
      </div>
      <div class="divider"></div>
      <div class="footer">
        <p>Sent by <a href="https://finowl.co.uk">FinOwl</a> on behalf of ${bizName}</p>
      </div>
    </div>
  </div>
</body>
</html>`;
}

// ─── processRecurringInvoices ────────────────────────────
// Creates invoices for all active recurring schedules where
// next_run_date <= today. Safe to run multiple times — only
// processes each record once per due cycle.
async function processRecurringInvoices() {
  const today = new Date().toISOString().slice(0, 10);
  let processed = 0;
  let errors = 0;

  try {
    const due = await pool.query(
      `SELECT * FROM recurring_invoices
        WHERE is_active = true AND next_run_date <= $1
        ORDER BY next_run_date ASC`,
      [today]
    );

    for (const rec of due.rows) {
      try {
        const tmpl = rec.template_data || {};
        const items = tmpl.items || [];

        // Calculate totals
        let subtotal = 0;
        for (const item of items) {
          subtotal += parseFloat(item.quantity || 1) * parseFloat(item.unit_price || 0);
        }
        const vatRateNum = parseFloat(tmpl.vat_rate || 0);
        const vatAmount  = parseFloat((subtotal * vatRateNum / 100).toFixed(2));
        const total      = parseFloat((subtotal + vatAmount).toFixed(2));

        // Compute due_date from template due_days (default 30)
        const dueDays = parseInt(tmpl.due_days || 30);
        const issueDate = today;
        const dueDate = new Date(today);
        dueDate.setDate(dueDate.getDate() + dueDays);
        const dueDateStr = dueDate.toISOString().slice(0, 10);

        const invNum = await nextInvoiceNumber(rec.user_id);
        const viewToken = require('crypto').randomBytes(32).toString('hex');

        const invRes = await pool.query(`
          INSERT INTO invoices
            (user_id, invoice_number, client_name, client_email, client_address,
             issue_date, due_date, notes, vat_rate, subtotal, vat_amount, total,
             status, view_token, auto_reminders_enabled)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'draft',$13,true)
          RETURNING *
        `, [
          rec.user_id, invNum,
          rec.client_name, rec.client_email || null,
          tmpl.client_address || null,
          issueDate, dueDateStr,
          tmpl.notes || null,
          vatRateNum,
          subtotal.toFixed(2), vatAmount, total,
          viewToken,
        ]);

        const invoice = invRes.rows[0];

        // Insert line items
        for (let i = 0; i < items.length; i++) {
          const item = items[i];
          const qty = parseFloat(item.quantity || 1);
          const price = parseFloat(item.unit_price || 0);
          const amount = parseFloat((qty * price).toFixed(2));
          await pool.query(
            `INSERT INTO invoice_items (invoice_id, description, quantity, unit_price, amount, sort_order)
             VALUES ($1,$2,$3,$4,$5,$6)`,
            [invoice.id, item.description || '', qty, price, amount, i]
          );
        }

        // Advance next_run_date and record last_run_date
        const nextRun = advanceByFrequency(rec.next_run_date, rec.frequency);
        await pool.query(
          `UPDATE recurring_invoices
              SET next_run_date = $1, last_run_date = $2, updated_at = NOW()
            WHERE id = $3`,
          [nextRun, today, rec.id]
        );

        // Auto-send: mark sent and email client
        if (rec.auto_send && rec.client_email) {
          await pool.query(
            `UPDATE invoices SET status = 'sent', sent_at = NOW(), updated_at = NOW()
              WHERE id = $1`,
            [invoice.id]
          );
          invoice.status = 'sent';
          invoice.sent_at = new Date().toISOString();

          const profile = await getBusinessProfile(rec.user_id);
          const bizName = (profile && profile.business_name) ? profile.business_name : 'Your service provider';
          const fmtGBP  = (n) => `£${parseFloat(n || 0).toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
          const fmtDate = (d) => d ? new Date(d).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }) : '—';

          const htmlBody = buildInvoiceEmailHtml({ invoice, items, profile });

          await sendInvoiceEmail({
            to: rec.client_email,
            subject: `Invoice ${invoice.invoice_number} from ${bizName} — ${fmtGBP(total)} due ${fmtDate(dueDateStr)}`,
            htmlBody,
          });
        }

        logAuditEvent({
          userId: rec.user_id,
          eventType: 'invoice_created',
          entityType: 'invoice',
          entityId: invoice.id,
          details: {
            invoice_number: invoice.invoice_number,
            client_name: rec.client_name,
            total: invoice.total,
            source: 'recurring',
            recurring_invoice_id: rec.id,
          },
        });

        processed++;
        console.log(`[RecurringInvoices] Created ${invoice.invoice_number} for user ${rec.user_id} (recurring #${rec.id})`);
      } catch (innerErr) {
        errors++;
        console.error(`[RecurringInvoices] Error processing recurring invoice #${rec.id}:`, innerErr);
      }
    }
  } catch (err) {
    console.error('[RecurringInvoices] Fatal error in processRecurringInvoices:', err);
  }

  console.log(`[RecurringInvoices] Done — ${processed} created, ${errors} errors`);
  return { processed, errors };
}

// ─── POST /api/recurring-invoices/process ────────────────
// Auth-required. Manually triggers the recurring invoice processor.
app.post('/api/recurring-invoices/process', authenticateToken, async (req, res) => {
  try {
    const result = await processRecurringInvoices();
    res.json({ success: true, ...result });
  } catch (err) {
    console.error('POST /api/recurring-invoices/process error:', err);
    res.status(500).json({ error: 'Failed to process recurring invoices' });
  }
});

// ─── POST /api/recurring-invoices ────────────────────────
app.post('/api/recurring-invoices', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const {
      client_name, client_email,
      template_data,
      frequency, next_run_date,
      is_active = true,
      auto_send = false,
    } = req.body;

    if (!client_name)    return res.status(400).json({ error: 'client_name required' });
    if (!frequency)      return res.status(400).json({ error: 'frequency required' });
    if (!next_run_date)  return res.status(400).json({ error: 'next_run_date required' });

    const valid = ['weekly', 'monthly', 'quarterly', 'yearly'];
    if (!valid.includes(frequency)) {
      return res.status(400).json({ error: `frequency must be one of: ${valid.join(', ')}` });
    }

    const r = await pool.query(`
      INSERT INTO recurring_invoices
        (user_id, client_name, client_email, template_data, frequency,
         next_run_date, is_active, auto_send)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING *
    `, [
      userId, client_name, client_email || null,
      JSON.stringify(template_data || {}),
      frequency, next_run_date, is_active, auto_send,
    ]);

    res.status(201).json({ success: true, recurring_invoice: r.rows[0] });
  } catch (err) {
    console.error('POST /api/recurring-invoices error:', err);
    res.status(500).json({ error: 'Failed to create recurring invoice' });
  }
});

// ─── GET /api/recurring-invoices ─────────────────────────
app.get('/api/recurring-invoices', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const r = await pool.query(
      `SELECT * FROM recurring_invoices
        WHERE user_id = $1
        ORDER BY next_run_date ASC, created_at DESC`,
      [userId]
    );
    res.json({ success: true, recurring_invoices: r.rows });
  } catch (err) {
    console.error('GET /api/recurring-invoices error:', err);
    res.status(500).json({ error: 'Failed to load recurring invoices' });
  }
});

// ─── PUT /api/recurring-invoices/:id ─────────────────────
app.put('/api/recurring-invoices/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { id } = req.params;

    const existing = await pool.query(
      `SELECT * FROM recurring_invoices WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );
    if (!existing.rows[0]) return res.status(404).json({ error: 'Not found' });

    const {
      client_name, client_email,
      template_data,
      frequency, next_run_date,
      is_active, auto_send,
    } = req.body;

    if (frequency) {
      const valid = ['weekly', 'monthly', 'quarterly', 'yearly'];
      if (!valid.includes(frequency)) {
        return res.status(400).json({ error: `frequency must be one of: ${valid.join(', ')}` });
      }
    }

    const r = await pool.query(`
      UPDATE recurring_invoices SET
        client_name   = COALESCE($3,  client_name),
        client_email  = COALESCE($4,  client_email),
        template_data = COALESCE($5,  template_data),
        frequency     = COALESCE($6,  frequency),
        next_run_date = COALESCE($7,  next_run_date),
        is_active     = COALESCE($8,  is_active),
        auto_send     = COALESCE($9,  auto_send),
        updated_at    = NOW()
      WHERE id = $1 AND user_id = $2
      RETURNING *
    `, [
      id, userId,
      client_name   || null,
      client_email  !== undefined ? (client_email || null) : null,
      template_data ? JSON.stringify(template_data) : null,
      frequency     || null,
      next_run_date || null,
      is_active     !== undefined ? is_active : null,
      auto_send     !== undefined ? auto_send : null,
    ]);

    res.json({ success: true, recurring_invoice: r.rows[0] });
  } catch (err) {
    console.error('PUT /api/recurring-invoices/:id error:', err);
    res.status(500).json({ error: 'Failed to update recurring invoice' });
  }
});

// ─── DELETE /api/recurring-invoices/:id ──────────────────
// Soft-deletes by setting is_active = false
app.delete('/api/recurring-invoices/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { id } = req.params;

    const r = await pool.query(
      `UPDATE recurring_invoices
          SET is_active = false, updated_at = NOW()
        WHERE id = $1 AND user_id = $2
        RETURNING id`,
      [id, userId]
    );

    if (!r.rows[0]) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  } catch (err) {
    console.error('DELETE /api/recurring-invoices/:id error:', err);
    res.status(500).json({ error: 'Failed to deactivate recurring invoice' });
  }
});

// ─── RECONCILIATION ROUTES ──────────────────────────────

// GET /api/reconciliation/summary
// Returns counts by reconciliation status + percentage complete
app.get('/api/reconciliation/summary', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { date_from, date_to } = req.query;

    let where = 'user_id = $1';
    const params = [userId];
    if (date_from) { params.push(date_from); where += ` AND date >= $${params.length}`; }
    if (date_to)   { params.push(date_to);   where += ` AND date <= $${params.length}`; }

    const r = await pool.query(`
      SELECT
        COUNT(*)                                                    AS total,
        COUNT(*) FILTER (WHERE reconciled_status = 'matched')       AS matched,
        COUNT(*) FILTER (WHERE reconciled_status = 'reviewed')      AS reviewed,
        COUNT(*) FILTER (WHERE reconciled_status = 'flagged')       AS flagged,
        COUNT(*) FILTER (WHERE reconciled_status = 'unmatched')     AS unmatched,
        COALESCE(SUM(ABS(amount)) FILTER (WHERE reconciled_status IN ('matched','reviewed')), 0) AS reconciled_amount
      FROM transactions
      WHERE ${where}
    `, params);

    const row = r.rows[0];
    const total = parseInt(row.total) || 0;
    const matched = parseInt(row.matched) || 0;
    const reviewed = parseInt(row.reviewed) || 0;
    const flagged = parseInt(row.flagged) || 0;
    const unmatched = parseInt(row.unmatched) || 0;
    const cleared = matched + reviewed;
    const percentage = total > 0 ? Math.round((cleared / total) * 100) : 0;

    res.json({
      total, matched, reviewed, flagged, unmatched,
      reconciled_amount: parseFloat(row.reconciled_amount) || 0,
      percentage
    });
  } catch (err) {
    console.error('GET /api/reconciliation/summary error:', err);
    res.status(500).json({ error: 'Failed to load reconciliation summary' });
  }
});

// GET /api/reconciliation
// Paginated transaction list with filters: status, date_from, date_to, category_id, amount_min, amount_max
app.get('/api/reconciliation', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const {
      status, date_from, date_to, category_id,
      amount_min, amount_max,
      page = '1', limit = '50',
      search
    } = req.query;

    const pageNum  = Math.max(1, parseInt(page) || 1);
    const limitNum = Math.min(200, Math.max(1, parseInt(limit) || 50));
    const offset   = (pageNum - 1) * limitNum;

    let where = 't.user_id = $1';
    const params = [userId];

    if (status && status !== 'all') {
      params.push(status);
      where += ` AND t.reconciled_status = $${params.length}`;
    }
    if (date_from) { params.push(date_from); where += ` AND t.date >= $${params.length}`; }
    if (date_to)   { params.push(date_to);   where += ` AND t.date <= $${params.length}`; }
    if (category_id) { params.push(parseInt(category_id)); where += ` AND t.category_id = $${params.length}`; }
    if (amount_min != null && amount_min !== '') { params.push(parseFloat(amount_min)); where += ` AND ABS(t.amount) >= $${params.length}`; }
    if (amount_max != null && amount_max !== '') { params.push(parseFloat(amount_max)); where += ` AND ABS(t.amount) <= $${params.length}`; }
    if (search) {
      params.push(`%${search}%`);
      where += ` AND (t.description ILIKE $${params.length} OR t.merchant_name ILIKE $${params.length})`;
    }

    const countRes = await pool.query(
      `SELECT COUNT(*) FROM transactions t WHERE ${where}`,
      params
    );
    const totalCount = parseInt(countRes.rows[0].count) || 0;

    const dataRes = await pool.query(`
      SELECT
        t.id, t.date, t.description, t.merchant_name, t.amount,
        t.reconciled_status, t.matched_at, t.reviewed_at, t.reconciliation_notes,
        t.ai_confidence, t.is_manually_categorised,
        c.name AS category_name, c.icon AS category_icon, c.color AS category_color, c.slug AS category_slug
      FROM transactions t
      LEFT JOIN categories c ON t.category_id = c.id
      WHERE ${where}
      ORDER BY
        CASE t.reconciled_status
          WHEN 'flagged'   THEN 1
          WHEN 'unmatched' THEN 2
          WHEN 'matched'   THEN 3
          WHEN 'reviewed'  THEN 4
          ELSE 5
        END,
        t.date DESC
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `, [...params, limitNum, offset]);

    res.json({
      transactions: dataRes.rows,
      total: totalCount,
      page: pageNum,
      pages: Math.ceil(totalCount / limitNum)
    });
  } catch (err) {
    console.error('GET /api/reconciliation error:', err);
    res.status(500).json({ error: 'Failed to load reconciliation transactions' });
  }
});

// PATCH /api/transactions/:id/reconciliation
// Update reconciliation_status and/or notes for a single transaction
app.patch('/api/transactions/:id/reconciliation', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const txId = parseInt(req.params.id);
    const { status, notes } = req.body;

    const allowed = ['unmatched', 'matched', 'reviewed', 'flagged'];
    if (status && !allowed.includes(status)) {
      return res.status(400).json({ error: `status must be one of: ${allowed.join(', ')}` });
    }

    // Build dynamic SET clause
    const sets = ['updated_at = NOW()'];
    const params = [userId, txId];

    if (status) {
      sets.push(`reconciled_status = $${params.length + 1}`);
      params.push(status);
      if (status === 'matched') {
        sets.push('matched_at = NOW()');
      } else if (status === 'reviewed') {
        sets.push('reviewed_at = NOW()');
      }
    }
    if (notes !== undefined) {
      sets.push(`reconciliation_notes = $${params.length + 1}`);
      params.push(notes || null);
    }

    if (sets.length === 1) {
      return res.status(400).json({ error: 'Provide status and/or notes to update' });
    }

    const r = await pool.query(`
      UPDATE transactions
      SET ${sets.join(', ')}
      WHERE user_id = $1 AND id = $2
      RETURNING id, reconciled_status, matched_at, reviewed_at, reconciliation_notes
    `, params);

    if (!r.rows[0]) return res.status(404).json({ error: 'Transaction not found' });

    logAuditEvent({
      userId,
      eventType: 'reconciliation_status_updated',
      entityType: 'transaction',
      entityId: txId,
      details: { status, notes: notes || null },
      req,
    });

    res.json({ success: true, transaction: r.rows[0] });
  } catch (err) {
    console.error('PATCH /api/transactions/:id/reconciliation error:', err);
    res.status(500).json({ error: 'Failed to update reconciliation status' });
  }
});

// POST /api/reconciliation/bulk-review
// Mark all 'matched' transactions (optionally filtered by date range) as 'reviewed'
app.post('/api/reconciliation/bulk-review', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { date_from, date_to } = req.body;

    let where = "user_id = $1 AND reconciled_status = 'matched'";
    const params = [userId];
    if (date_from) { params.push(date_from); where += ` AND date >= $${params.length}`; }
    if (date_to)   { params.push(date_to);   where += ` AND date <= $${params.length}`; }

    const r = await pool.query(`
      UPDATE transactions
      SET reconciled_status = 'reviewed', reviewed_at = NOW(), updated_at = NOW()
      WHERE ${where}
      RETURNING id
    `, params);

    const count = r.rows.length;

    logAuditEvent({
      userId,
      eventType: 'reconciliation_bulk_reviewed',
      entityType: 'transaction',
      entityId: null,
      details: { count, date_from: date_from || null, date_to: date_to || null },
      req,
    });

    res.json({ success: true, count });
  } catch (err) {
    console.error('POST /api/reconciliation/bulk-review error:', err);
    res.status(500).json({ error: 'Failed to bulk review transactions' });
  }
});

// ─── Sentry Error Handler ────────────────────────────────
// Must be AFTER all routes, BEFORE the generic error handler.
// Captures unhandled exceptions and sends them to Sentry.
app.use(Sentry.errorHandler());

// ─── Generic 500 Handler ─────────────────────────────────
// Fallback error handler — must come after Sentry's errorHandler.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[server] unhandled error:', err);
  const status = err.status || err.statusCode || 500;
  res.status(status).json({ error: err.message || 'Internal Server Error' });
});

// ─── Server Start ───────────────────────────────────────
// Render terminates TLS at its load balancer and serves HTTP/2 to clients
// automatically. The app runs plain HTTP/1.1 behind the proxy — this is the
// correct architecture. No application-level HTTP/2 or TLS config needed.
app.listen(port, () => 
  console.log(`FinOwl server running on port ${port}`);
  // Log Stripe configuration status at startup
  if (process.env.STRIPE_SECRET_KEY) {
    console.log('[stripe-direct] ✓ Stripe configured — direct account checkout sessions active');
    if (process.env.STRIPE_WEBHOOK_SECRET) {
      console.log('[stripe-direct] ✓ Webhook signing secret set — POST /api/webhook ready');
    } else {
      console.warn('[stripe-direct] ⚠ STRIPE_WEBHOOK_SECRET not set — webhooks will be rejected');
    }
  } else {
    console.warn('[stripe-direct] ⚠ STRIPE_SECRET_KEY not set — checkout will fall back to static (USD) payment links');
  }
  startNotificationScheduler(pool);
  // Run recurring invoice processor at startup to catch any missed schedules
  processRecurringInvoices().catch(err =>
    console.error('[RecurringInvoices] Startup run failed:', err)
  )
});
