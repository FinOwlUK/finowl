# FinOwl

Autonomous bookkeeping for UK sole traders and small business.

**Live:** https://finowl.co.uk | https://finowl.polsia.app

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | Neon PostgreSQL connection string |
| `PORT` | No | Server port (default: 3000) |
| `SENTRY_DSN` | Recommended | Sentry error monitoring DSN (from sentry.io) |
| `POLSIA_EMAIL_BASE_URL` | Yes | Polsia email proxy base URL |
| `POLSIA_API_KEY` | Yes | Polsia API key for email proxy |
| `EMAIL_FROM` | No | Sender address (default: `FinOwl <noreply@finowl.co.uk>`) |
| `APP_URL` | No | Public URL (default: `https://finowl.co.uk`) |

---

## Sentry Error Monitoring

Backend errors are captured via `@sentry/node` (initialised in `sentry.js`).
Client-side errors in browser pages are captured via `@sentry/browser`
loaded from CDN on dashboard, login, signup, and reset-password pages.

### Setup

1. Create a Sentry project at [sentry.io](https://sentry.io) (org: finowl, project: finowl)
2. Copy the DSN (looks like `https://...@sentry.io/PROJECT_ID`)
3. Set `SENTRY_DSN` env var in Render dashboard
4. Performance monitoring is enabled at 10% sample rate in production

### Source Maps (optional, for readable stack traces)

For better stack traces in Sentry's UI:

1. Install `@sentry/cli` as a dev dependency:
   ```
   npm install --save-dev @sentry/cli
   ```

2. Authenticate once:
   ```
   npx sentry-cli auth
   ```

3. After each production deploy, run:
   ```
   SENTRY_DSN=https://...@sentry.io/PROJECT_ID \
   SENTRY_ORG=finowl \
   SENTRY_PROJECT=finowl \
   node scripts/upload-sourcemaps.js
   ```

The `render.yaml` already includes `--enable-source-maps` in the start command.

---

## Transactional Email

Email is sent via the Polsia email proxy (`email.js` → Polsia API).
No Postmark/SendGrid API keys needed — the proxy handles delivery.

**Features wired:**
- Invoice send → `sendInvoiceEmail()` in `/api/invoices/:id/send`
- Accountant invite → `sendInviteEmail()` in `/api/team/invite`
- Auth emails (verify, reset) → `sendAuthEmail()` in auth routes
- Notifications (VAT reminders, alerts) → `notifications.js` via `sendEmail()`

All emails use the branded HTML template in `email.js` (`wrapHtml()`).

### Custom Sender Domain (finowl.co.uk)

To send from `@finowl.co.uk` instead of `@polsia.app`, you need to verify
ownership by adding DNS records to `finowl.co.uk`:

**Postmark (recommended — best deliverability):**

| Type | Name | Value |
|---|---|---|
| CNAME | `mail` | `mail.postmarkapp.com` |
| CNAME | `s1._domainkey` | `s1.domainkey.postmarkapp.com` |
| CNAME | `s2._domainkey` | `s2.domainkey.postmarkapp.com` |
| TXT | `@` | `v=spf1 include:spf.postmarkapp.com ~all` |

After adding records, verify in Postmark dashboard → "DNS Verification".

**SendGrid (free tier alternative):**

| Type | Name | Value |
|---|---|---|
| TXT | `@` | `v=spf1 include:sendgrid.net ~all` |
| CNAME | `s1._domainkey` | `s1.domainkey.sendgrid.net` |
| CNAME | `smtp._domainkey` | `smtp.domainkey.sendgrid.net` |

After adding records, verify in SendGrid → "Sender Authentication".

**Interim sender** (until DNS is verified):
Set `EMAIL_FROM=FinOwl <finowl@polsia.app>` in Render dashboard.

---

## Local Development

```bash
npm install
cp .env.example .env  # add your DATABASE_URL, SENTRY_DSN, etc.
npm run dev
```

## Deployment

Render auto-deploys on push to main. `render.yaml` sets:
- `buildCommand: npm install`
- `startCommand: node --enable-source-maps node_modules/.bin/migrate && node --enable-source-maps server.js`
- `NODE_ENV: production`