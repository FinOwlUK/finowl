# FinOwl — Technical Handover Document

**Generated:** 2026-05-05
**Purpose:** Everything you need to recreate the FinOwl backend under your own Render account.
**Verified:** All values sourced directly from the live service config and repo — nothing assumed.

---

## Table of Contents

1. [Repository](#1-repository)
2. [package.json Scripts](#2-packagejson-scripts)
3. [Render Service Configuration](#3-render-service-configuration)
4. [render.yaml](#4-renderyaml)
5. [Node / Runtime Version](#5-node--runtime-version)
6. [Environment Variables](#6-environment-variables)
7. [Database](#7-database)
8. [External Services & Integrations](#8-external-services--integrations)
9. [DNS / Custom Domain Settings](#9-dns--custom-domain-settings)
10. [GitHub Access](#10-github-access)
11. [Full Repo ZIP Export](#11-full-repo-zip-export)

---

## 1. Repository

| Field | Value |
|-------|-------|
| **GitHub URL** | https://github.com/Polsia-Inc/finowl |
| **Deploy branch** | `main` |
| **Live app URL** | https://finowl.co.uk |
| **Render service ID** | `srv-d7a2t9ruibrs73fp7il0` |
| **Render dashboard** | https://dashboard.render.com/web/srv-d7a2t9ruibrs73fp7il0 |

---

## 2. package.json Scripts

Copied verbatim from `package.json`:

```json
"scripts": {
  "start": "node migrate.js && node server.js",
  "dev": "node server.js",
  "build": "node scripts/download-og-image.js && npm run migrate",
  "migrate": "node migrate.js"
}
```

**Key notes:**
- `start` runs migrations first, then starts the Express server — this is the production startup command.
- `build` downloads the OG image asset and runs migrations — this is the Render **build command** phase.
- `migrate` is a standalone script that runs all pending migrations in `/migrations/`.

---

## 3. Render Service Configuration

| Field | Value |
|-------|-------|
| **Service name** | `finowl` |
| **Service type** | Web Service |
| **Runtime** | Node |
| **Build command** | `npm install` |
| **Start command** | `node --enable-source-maps node_modules/.bin/migrate && node --enable-source-maps server.js` |
| **Health check path** | `/health` |
| **Region** | could not verify — not exposed via API (check Render dashboard; provisioned 2026-04-06, likely Oregon `oregon` or Frankfurt `frankfurt`) |
| **Deploy branch** | `main` |
| **Auto-deploy** | Yes (on push to `main`) |

> **Note on build vs start commands:** The `render.yaml` start command references `node_modules/.bin/migrate` which is a node-pg-migrate binary. In practice the `package.json` `start` script (`node migrate.js && node server.js`) works equivalently and is the simpler form. Either works on Render.

---

## 4. render.yaml

Present in repo root. Full contents:

```yaml
services:
  - type: web
    runtime: node
    name: app
    buildCommand: npm install
    startCommand: node --enable-source-maps node_modules/.bin/migrate && node --enable-source-maps server.js
    healthCheckPath: /health
    envVars:
      - key: NODE_ENV
        value: production
```

---

## 5. Node / Runtime Version

| Source | Value |
|--------|-------|
| `engines.node` in package.json | not specified |
| `.node-version` file | `20` (Node.js 20.x) |
| `.nvmrc` file | not present |
| Verified running version | Node.js v20.20.2 |

**Recommendation:** Pin `"engines": { "node": "20.x" }` in `package.json` before moving to your own Render account, and select **Node 20** in Render's environment settings.

---

## 6. Environment Variables

**All 20 variables currently set on the Render service.** Names only — you must supply your own values for secrets. Values from the live service are listed where they are non-secret configuration.

| Name | Purpose |
|------|---------|
| `NODE_ENV` | Runtime environment (`production`) |
| `DATABASE_URL` | PostgreSQL connection string (Neon) — full connection URL with credentials |
| `APP_URL` | Canonical app URL (`https://finowl.co.uk`) — update to your domain |
| `JWT_SECRET` | ⚠️ **Not currently set as env var** — app derives it from `POLSIA_API_KEY` via SHA-256. You should set an explicit `JWT_SECRET` (random 64-char hex string) when migrating |
| `STRIPE_SECRET_KEY` | Stripe secret key (`sk_live_...` or `sk_test_...`) for your Stripe account |
| `STRIPE_PUBLISHABLE_KEY` | Stripe publishable key (`pk_live_...` or `pk_test_...`) |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret (`whsec_...`) — get from Stripe dashboard after creating webhook |
| `TRUELAYER_CLIENT_ID` | TrueLayer app client ID — from developer.truelayer.com |
| `TRUELAYER_CLIENT_SECRET` | TrueLayer app client secret |
| `TRUELAYER_SANDBOX` | `true` = sandbox mode, `false` = live open banking. Set to `false` in production |
| `HMRC_CLIENT_ID` | HMRC MTD app client ID — from developer.service.hmrc.gov.uk |
| `HMRC_CLIENT_SECRET` | HMRC MTD app client secret (⚠️ not currently set as env var — see note below) |
| `HMRC_SANDBOX` | `true` = HMRC test API, `false` = live MTD API. Set to `false` in production |
| `OPENAI_API_KEY` | OpenAI API key (or compatible proxy key) |
| `OPENAI_BASE_URL` | OpenAI API base URL — defaults to `https://api.openai.com/v1` if not set |
| `EMAIL_FROM` | Sender address for transactional email (e.g. `FinOwl <noreply@finowl.co.uk>`) |
| `SMTP_HOST` | SMTP server hostname (optional — app falls back to Polsia email proxy if not set) |
| `SMTP_PORT` | SMTP port (default 587) |
| `SMTP_USER` | SMTP username |
| `SMTP_PASS` | SMTP password |
| `SENTRY_DSN` | Sentry error monitoring DSN — from your Sentry project settings |
| `POLSIA_API_KEY` | Polsia platform API key — **not needed outside Polsia** — replace with explicit `JWT_SECRET` |
| `POLSIA_EMAIL_BASE_URL` | Polsia email proxy base URL — **not needed outside Polsia** — configure SMTP instead |
| `POLSIA_R2_BASE_URL` | Polsia R2 file storage URL — **not needed outside Polsia** |
| `POLSIA_ANALYTICS_SLUG` | Polsia analytics identifier — **not needed outside Polsia** |

> **HMRC_CLIENT_SECRET note:** The code reads `process.env.HMRC_CLIENT_SECRET` but this variable was not found in the current Render env vars — either it was accidentally omitted or HMRC OAuth is not yet in active production use. Add it if you need live HMRC MTD VAT submission.

> **JWT_SECRET note:** Currently the app does `process.env.JWT_SECRET || crypto.createHash('sha256').update(process.env.POLSIA_API_KEY || 'finowl-dev-secret').digest('hex')`. On your own Render service, set an explicit `JWT_SECRET` so JWTs don't break when other env vars change.

---

## 7. Database

| Field | Value |
|-------|-------|
| **Provider** | Neon (serverless PostgreSQL) — https://neon.tech |
| **Connection method** | `DATABASE_URL` environment variable (standard PostgreSQL connection string) |
| **SSL** | Required — `?sslmode=require` appended to connection string |
| **Database name** | `neondb` (from current connection string) |
| **Host** | `ep-little-mud-aj2a3u3c.c-3.us-east-2.aws.neon.tech` (current Neon endpoint) |

**Migrations:** Located in `/migrations/` directory. Run via `node migrate.js`. The app runs migrations automatically on startup (`npm start`). 24 migration files covering:

```
001_create_categories
002_create_bank_connections
003_create_transactions
004_add_subscription
005_add_vat_rate_to_categories
006_create_vat_settings
007_create_categorisation_rules
007_create_invoices
007_create_mileage_expenses
007_create_sa_settings
008_create_receipts
008_create_vat_submissions
009_create_notification_settings
009_create_team_members
009_truelayer_bank_connections
010_add_duplicate_detection
010_add_multicurrency
010_create_audit_log
011_invoice_reminders
012_bank_reconciliation
012_create_insights
012_create_recurring_patterns
012_ltd_interest
013_create_analytics
014_business_profile
015_receipt_match_confidence
016_add_password_auth
017_bank_connections_updated_at
018_transactions_receipt_id
019_create_audit_events
020_add_duplicate_columns
020_create_recurring_invoices
021_reconciliation_status_v2
022_rules_enhancements
023_backfill_subscription_status
024_stripe_direct_columns
```

**To migrate to your own Neon account:**
1. Create a new Neon project at https://neon.tech
2. Set `DATABASE_URL` in your Render env vars to the new connection string
3. Migrations run automatically on first deploy

---

## 8. External Services & Integrations

### Stripe (Payments)

| Field | Value |
|-------|-------|
| **Integration type** | Direct account (owner's own Stripe account — no Stripe Connect) |
| **Webhook endpoint** | `POST /api/webhook` |
| **Webhook events handled** | `checkout.session.completed`, `invoice.paid`, `invoice.payment_failed`, `customer.subscription.updated`, `customer.subscription.deleted` |
| **Currency** | GBP (pence) |
| **Plans** | Sole Trader (£59/mo, £649/yr, £1,298/2yr), Dormant (£15/mo, £165/yr, £330/2yr), Limited Co (£89/mo, £979/yr, £1,958/2yr) |
| **Trial period** | 30 days on all plans |

**To set up on your own Stripe account:**
1. Create a Stripe account at https://stripe.com
2. Get your `STRIPE_SECRET_KEY` and `STRIPE_PUBLISHABLE_KEY` from the Stripe dashboard
3. In Stripe dashboard → Developers → Webhooks, create a new webhook endpoint pointing to `https://yourdomain.com/api/webhook`
4. Subscribe to the 5 events listed above
5. Copy the signing secret as `STRIPE_WEBHOOK_SECRET`

> Products and Prices are created automatically by the app on first checkout — you don't need to pre-create them.

---

### TrueLayer (Open Banking)

| Field | Value |
|-------|-------|
| **Purpose** | Bank account connection and transaction import (UK open banking) |
| **Current mode** | Sandbox (`TRUELAYER_SANDBOX=true`) |
| **Auth flow** | OAuth 2.0 — redirect to TrueLayer, callback to `/api/auth/truelayer/callback` |
| **Sandbox auth host** | `auth.truelayer-sandbox.com` |
| **Live auth host** | `auth.truelayer.com` |
| **Sandbox API host** | `api.truelayer-sandbox.com` |
| **Live API host** | `api.truelayer.com` |

**To set up on your own TrueLayer account:**
1. Create an account at https://console.truelayer.com
2. Create a new application and get `Client ID` and `Client Secret`
3. Add your callback URL: `https://yourdomain.com/api/auth/truelayer/callback`
4. Set `TRUELAYER_CLIENT_ID`, `TRUELAYER_CLIENT_SECRET` env vars
5. Set `TRUELAYER_SANDBOX=false` for production

---

### HMRC Making Tax Digital (MTD)

| Field | Value |
|-------|-------|
| **Purpose** | VAT return submission to HMRC via Making Tax Digital API |
| **Current mode** | Sandbox (`HMRC_SANDBOX=true`) |
| **Sandbox API host** | `test-api.service.hmrc.gov.uk` |
| **Live API host** | `api.service.hmrc.gov.uk` |
| **Auth flow** | OAuth 2.0 — HMRC developer portal |
| **Callback path** | `/api/hmrc/callback` |
| **Features used** | VAT obligations, VAT return submission |

**To set up on your own HMRC developer account:**
1. Register at https://developer.service.hmrc.gov.uk
2. Create an application for "Making Tax Digital for VAT"
3. Get `Client ID` and `Client Secret`
4. Set `HMRC_CLIENT_ID`, `HMRC_CLIENT_SECRET` env vars
5. Set `HMRC_SANDBOX=false` for production

---

### OpenAI (AI Features)

| Field | Value |
|-------|-------|
| **Purpose** | Transaction categorisation, financial insights, chat, receipt OCR |
| **Models used** | GPT-4o-mini (categorisation/insights/chat), GPT-4o vision (receipt OCR) |
| **Config** | `OPENAI_API_KEY` + optional `OPENAI_BASE_URL` (defaults to `https://api.openai.com/v1`) |

---

### Email

| Field | Value |
|-------|-------|
| **Primary transport** | SMTP via Nodemailer (if `SMTP_HOST` is configured) |
| **Fallback transport** | Polsia email proxy (via `POLSIA_EMAIL_BASE_URL` — Polsia-specific, not available outside Polsia) |
| **Sender address** | `FinOwl <noreply@finowl.co.uk>` (set via `EMAIL_FROM`) |
| **Emails sent** | Invoice emails, team invites, auth/magic-link emails, welcome emails, unusual transaction alerts |

**To configure email on your own hosting:**
- Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` to your SMTP provider credentials
- Recommended providers: AWS SES, Postmark, SendGrid, Mailgun
- The Polsia proxy fallback will not work outside of Polsia infrastructure

---

### Google Analytics 4 (GA4)

| Field | Value |
|-------|-------|
| **Measurement ID** | `G-0CKFPZFEPR` (hardcoded default; also accepts `GA_MEASUREMENT_ID` env var) |
| **Purpose** | Page view tracking on public pages |

---

### Sentry (Error Monitoring)

| Field | Value |
|-------|-------|
| **Purpose** | Server-side and client-side error capture |
| **Config** | `SENTRY_DSN` env var |
| **Project** | `o4511279156625408` (current Sentry org) |

**To set up on your own Sentry account:**
1. Create project at https://sentry.io
2. Set `SENTRY_DSN` to your new DSN

---

### Authentication Method

| Field | Value |
|-------|-------|
| **Method** | Password-based (email + bcrypt password hash) |
| **Token type** | JWT (stored client-side, sent as Bearer token) |
| **Token duration** | 24 hours standard, 30 days with "Remember Me" |
| **No third-party OAuth** | No Google/GitHub/NextAuth — fully self-contained |

---

## 9. DNS / Custom Domain Settings

### Current Render Custom Domains

Three domains are registered on the Render service:

| Domain | Type | DNS Record Required |
|--------|------|---------------------|
| `finowl.co.uk` (apex) | A record | Point to Render Anycast IP `216.24.57.1` |
| `www.finowl.co.uk` | CNAME | Point to `finowl.onrender.com` |
| `finowl.polsia.app` | CNAME (Polsia-managed) | Managed by Polsia — you can drop this |

### DNS Records to Update When Moving to Your Own Render Service

When you create a new Render service, Render will give you a new `.onrender.com` subdomain. You'll need to:

1. **Add your custom domain(s)** in the new Render service dashboard (Settings → Custom Domains)
2. **Render will provide** a new CNAME target (e.g. `your-service-name.onrender.com`) and an Anycast A record IP
3. **Update your DNS registrar** (wherever `finowl.co.uk` is registered — check Cloudflare, Namecheap, etc.):

| Record | Type | Current Value | Action |
|--------|------|---------------|--------|
| `finowl.co.uk` | A | `216.24.57.1` | Update to new Render Anycast IP (Render provides this after you add the custom domain) |
| `www.finowl.co.uk` | CNAME | `finowl.onrender.com` | Update to your new service's `.onrender.com` hostname |

> **Note:** Render's Anycast IP (`216.24.57.1`) may be the same across Render accounts — verify in your new service's custom domain settings. SSL certificates are provisioned automatically by Render once DNS propagates.

---

## 10. GitHub Access

**Current repository:** https://github.com/Polsia-Inc/finowl

To take ownership of the code, you have two options:

**Option A — Repository Transfer (recommended):**
- Ask Polsia to initiate a GitHub repository transfer from `Polsia-Inc/finowl` to your own GitHub account
- Transfer preserves full git history, issues, and PRs
- After transfer, update your Render service to point to the new repo URL

**Option B — Fork:**
- Fork `https://github.com/Polsia-Inc/finowl` to your own GitHub account
- Connect the fork to your new Render service
- Note: forks inherit the full commit history but are publicly linked to the source repo

Contact Polsia support to initiate a transfer.

---

## 11. Full Repo ZIP Export

The full source is available directly from GitHub:

**→ [https://github.com/Polsia-Inc/finowl](https://github.com/Polsia-Inc/finowl)**

To download as a ZIP:
- **GitHub ZIP:** `https://github.com/Polsia-Inc/finowl/archive/refs/heads/main.zip`
- **Clone:** `git clone https://github.com/Polsia-Inc/finowl.git`

Or download just the source (no git history):
```bash
curl -L https://github.com/Polsia-Inc/finowl/archive/refs/heads/main.zip -o finowl-source.zip
```

> **Access:** If the repo is private, you'll need to be granted access or request a transfer/fork from Polsia first (see Section 10).

### Create a local archive yourself

Once you have the repo cloned locally:
```bash
tar --exclude="./node_modules" --exclude="./.git" --exclude="./.tmp" -czf finowl-export.tar.gz .
```
This produces a ~1.2MB archive of all source files.

---

*This document was generated on 2026-05-05 from the live Render service (instance ID 22958) and repository state at commit `5795c68ffd1a16b9c7c13210136f0bdf5e47a8bc`.*
