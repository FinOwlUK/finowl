/**
 * FinOwl Email Service
 *
 * Dual-transport transactional email:
 *   1. SMTP (via Nodemailer)  - if SMTP_HOST is configured
 *   2. Polsia email proxy     - fallback if SMTP not configured
 *
 * Env vars (SMTP):
 *   SMTP_HOST   - SMTP server hostname
 *   SMTP_PORT   - SMTP port (default 587)
 *   SMTP_USER   - SMTP username
 *   SMTP_PASS   - SMTP password
 *   EMAIL_FROM  - sender address e.g. "FinOwl <noreply@finowl.co.uk>"
 *
 * Env vars (Polsia proxy):
 *   POLSIA_EMAIL_BASE_URL  - base URL of the Polsia email proxy
 *   POLSIA_API_KEY         - Polsia API key
 */

// Load nodemailer lazily so app starts without it if not installed yet
let nodemailer = null;
try {
  nodemailer = require('nodemailer');
} catch (e) {
  // nodemailer not installed yet - SMTP transport unavailable
}

// SMTP config
const SMTP_HOST  = process.env.SMTP_HOST;
const SMTP_PORT  = parseInt(process.env.SMTP_PORT || '587', 10);
const SMTP_USER  = process.env.SMTP_USER;
const SMTP_PASS  = process.env.SMTP_PASS;
const EMAIL_FROM = process.env.EMAIL_FROM || 'FinOwl <noreply@finowl.co.uk';

// Polsia proxy config
const EMAIL_PROXY_URL = process.env.POLSIA_EMAIL_BASE_URL;
const POLSIA_API_KEY  = process.env.POLSIA_API_KEY;

// Build SMTP transporter once (null if not configured)
let _smtpTransport = null;
function getSmtpTransport() {
  if (!nodemailer) return null;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) return null;
  if (_smtpTransport) return _smtpTransport;
  _smtpTransport = nodemailer.createTransport({
    host:     SMTP_HOST,
    port:     SMTP_PORT,
    secure:   SMTP_PORT === 465,           // true for port 465, else STARTTLS
    auth:     { user: SMTP_USER, pass: SMTP_PASS },
    // Retry logic for transient failures
    maxConnections: 5,
    maxMessages: 100,
  });
  return _smtpTransport;
}

// Is SMTP available?
const _hasSmtp = !!(SMTP_HOST && SMTP_USER && SMTP_PASS && nodemailer);

// Log which transport is active
if (_hasSmtp) {
  console.log('[Email] SMTP transport configured:', SMTP_HOST, ':' + SMTP_PORT);
} else if (EMAIL_PROXY_URL && POLSIA_API_KEY) {
  console.log('[Email] Polsia proxy transport configured:', EMAIL_PROXY_URL);
} else {
  console.warn('[Email] No email transport configured! Emails will be logged only.');
}

// Counter for audit trail
let _emailCount = 0;

// Helper to build audit log entry
function _logEmail(type, to, subject, transport, status, extra = {}) {
  _emailCount++;
  const entry = {
    n: _emailCount,
    ts: new Date().toISOString(),
    type,
    to,
    subject,
    transport,   // 'smtp' | 'polsia' | 'skipped' | 'logged'
    status,      // 'ok' | 'skipped' | 'error'
    ...extra,
  };
  if (status === 'error') {
    console.error('[Email][AUDIT]', JSON.stringify(entry));
  } else if (transport === 'logged') {
    console.log('[Email][AUDIT][SIMULATED]', JSON.stringify(entry));
  } else {
    console.log('[Email][AUDIT]', JSON.stringify(entry));
  }
}

// Validate recipient
function _validRecipient(to) {
  return to && typeof to === 'string' && to.includes('@') && to.includes('.');
}

// Core send function - tries SMTP, then Polsia proxy, then logs
async function sendEmail({ to, subject, htmlBody, textBody, from, metadata = {} }) {
  // Validate recipient
  if (!_validRecipient(to)) {
    console.warn('[Email] Invalid recipient - skipping:', to, metadata);
    return { ok: false, error: 'invalid_recipient' };
  }

  const fromAddr = from || EMAIL_FROM;
  const meta     = { ...metadata, email_n: _emailCount + 1 };

  // --- Transport 1: SMTP ---
  if (_hasSmtp) {
    try {
      const transport = getSmtpTransport();
      const info = await transport.sendMail({
        from:    fromAddr,
        to,
        subject,
        html:    htmlBody || undefined,
        text:    textBody || undefined,
      });
      // Nodemailer doesn't expose messageId reliably across transports,
      // so we use the internal id from sendMail response
      _logEmail(metadata.type || 'generic', to, subject, 'smtp', 'ok', {
        messageId: info.messageId || info.messageId,
      });
      return { ok: true, transport: 'smtp', messageId: info.messageId };
    } catch (err) {
      console.error('[Email] SMTP send failed, trying Polsia proxy:', err.message);
      // fall through to Polsia proxy
    }
  }

  // --- Transport 2: Polsia proxy ---
  if (EMAIL_PROXY_URL && POLSIA_API_KEY) {
    try {
      const resp = await fetch(`${EMAIL_PROXY_URL}/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${POLSIA_API_KEY}`,
        },
        body: JSON.stringify({
          to,
          from: fromAddr,
          subject,
          html: htmlBody,
          ...(textBody ? { text: textBody } : {}),
        }),
      });

      if (!resp.ok) {
        const body = await resp.text().catch(() => '');
        console.error(`[Email] Proxy error ${resp.status} -> ${to}:`, body, meta);
        _logEmail(metadata.type || 'generic', to, subject, 'polsia', 'error', {
          statusCode: resp.status,
          body: body.slice(0, 200),
        });
        return { ok: false, error: `proxy_${resp.status}` };
      }

      _logEmail(metadata.type || 'generic', to, subject, 'polsia', 'ok');
      return { ok: true, transport: 'polsia' };
    } catch (err) {
      console.error(`[Email] Polsia proxy failed -> ${to}:`, err.message, meta);
      _logEmail(metadata.type || 'generic', to, subject, 'polsia', 'error', {
        error: err.message,
      });
      return { ok: false, error: err.message };
    }
  }

  // --- Transport 3: Log only (graceful degradation) ---
  console.log('[Email][SIMULATED] Would send email:', {
    to, from: fromAddr, subject,
    htmlLength: htmlBody ? htmlBody.length : 0,
    textLength: textBody ? textBody.length : 0,
  });
  _logEmail(metadata.type || 'generic', to, subject, 'logged', 'ok');
  return { ok: true, skipped: true, reason: 'no_transport_configured' };
}

// Convenience: send via SMTP directly when you know SMTP is configured
async function sendSmtpEmail({ to, subject, htmlBody, textBody, from }) {
  if (!_hasSmtp) {
    return { ok: false, error: 'smtp_not_configured' };
  }
  const fromAddr = from || EMAIL_FROM;
  try {
    const transport = getSmtpTransport();
    const info = await transport.sendMail({
      from: fromAddr, to, subject,
      html: htmlBody || undefined,
      text: textBody || undefined,
    });
    _logEmail('smtp_direct', to, subject, 'smtp', 'ok', { messageId: info.messageId });
    return { ok: true, transport: 'smtp', messageId: info.messageId };
  } catch (err) {
    console.error('[Email] SMTP direct send failed:', err.message);
    return { ok: false, error: err.message };
  }
}

// Convenience: send via Polsia proxy directly
async function sendPolsiaEmail({ to, subject, htmlBody, textBody, from }) {
  if (!EMAIL_PROXY_URL || !POLSIA_API_KEY) {
    return { ok: false, error: 'polsia_not_configured' };
  }
  const fromAddr = from || EMAIL_FROM;
  try {
    const resp = await fetch(`${EMAIL_PROXY_URL}/send`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${POLSIA_API_KEY}`,
      },
      body: JSON.stringify({ to, from: fromAddr, subject, html: htmlBody, ...(textBody ? { text: textBody } : {}) }),
    });
    if (!resp.ok) {
      return { ok: false, error: `proxy_${resp.status}` };
    }
    _logEmail('polsia_direct', to, subject, 'polsia', 'ok');
    return { ok: true, transport: 'polsia' };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

// Convenience wrappers used by server.js
async function sendAuthEmail({ to, subject, htmlBody }) {
  return sendEmail({ to, subject, htmlBody, metadata: { type: 'auth' } });
}

async function sendInvoiceEmail({ to, subject, htmlBody }) {
  return sendEmail({ to, subject, htmlBody, metadata: { type: 'invoice' } });
}

async function sendInviteEmail({ to, ownerEmail, inviteUrl, htmlBody: customHtml }) {
  const htmlBody = customHtml || wrapHtml(`
    <p>${ownerEmail} has invited you to access their FinOwl account as a read-only accountant.</p>
    <p>You'll be able to view their transactions, VAT returns, expenses, invoices, and financial reports.</p>
    <a href="${inviteUrl}" class="cta-btn">Accept Invite &rarr;</a>
    <p style="font-size:13px;color:#9ca3af;margin-top:16px">This link is valid for 30 days. If you didn't expect this email, safely ignore it.</p>
  `, { subtitle: "You've been invited to view FinOwl books" });

  return sendEmail({
    to,
    subject: `${ownerEmail} invited you to their FinOwl account`,
    htmlBody,
    metadata: { type: 'team_invite' },
  });
}

// Send welcome email after registration
async function sendWelcomeEmail({ to, name, email }) {
  const firstName = (name && name !== email) ? name.split('@')[0].trim() : email.split('@')[0].trim();
  const htmlBody = wrapHtml(`
    <p>Hi ${firstName},</p>
    <p>Welcome to <strong>FinOwl</strong> &mdash; autonomous bookkeeping for UK sole traders and small businesses.</p>
    <p>Here's what you can do right now:</p>
    <ul style="color:#4b5563;font-size:15px;line-height:1.8;margin:16px 0 16px 20px;">
      <li>Connect your bank account (Starling or any UK bank via Open Banking)</li>
      <li>Add expenses and see them auto-categorised with VAT rates</li>
      <li>Track mileage and generate receipt uploads</li>
      <li>File your VAT returns directly to HMRC (MTD compliant)</li>
      <li>Create and send invoices to clients</li>
    </ul>
    <p>Need help? Reply to this email or visit <a href="https://finowl.co.uk" style="color:#d4920b;">finowl.co.uk</a> for guides and support.</p>
    <p style="margin-top:20px;color:#6b7280;font-size:14px;">Your account is active &mdash; no further setup needed. Get started by connecting your bank in the dashboard.</p>
  `, {
    title: 'Welcome to FinOwl!',
    subtitle: 'Your autonomous bookkeeping assistant is ready.',
  });

  return sendEmail({
    to,
    subject: `Welcome to FinOwl, ${firstName}!`,
    htmlBody,
    metadata: { type: 'welcome' },
  });
}

// Send password reset email
async function sendPasswordResetEmail({ to, resetUrl }) {
  const htmlBody = wrapHtml(`
    <p>We received a request to reset the password for your FinOwl account.</p>
    <p>Click the button below to set a new password:</p>
    <a href="${resetUrl}" class="cta-btn">Reset password</a>
    <p style="margin-top:20px;color:#9ca3af;font-size:13px;">This link expires in 1 hour. If you didn't request a reset, you can safely ignore this email &mdash; your account is secure.</p>
    <p style="margin-top:12px;font-size:12px;color:#9ca3af;">Or copy this link into your browser:<br><span style="word-break:break-all;">${resetUrl}</span></p>
  `, {
    title: 'Reset your FinOwl password',
    subtitle: '',
  });

  return sendEmail({
    to,
    subject: 'Reset your FinOwl password',
    htmlBody,
    metadata: { type: 'password_reset' },
  });
}

// HTML email wrapper with FinOwl branding
function wrapHtml(content, { title = '', subtitle = '' } = {}) {
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
    h2 { font-size:22px; font-weight:700; margin-bottom:6px; }
    p.sub { color:#6b7280; font-size:14px; margin-bottom:20px; line-height:1.6; }
    .divider { height:1px; background:#e5e2db; margin:20px 0; }
    .footer { margin-top:20px; text-align:center; font-size:12px; color:#9ca3af; }
    .footer a { color:#d4920b; text-decoration:none; }
    .cta-btn { display:inline-block; background:#d4920b; color:#fff; text-decoration:none; padding:12px 24px; border-radius:8px; font-weight:600; font-size:14px; margin-top:20px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <span class="header-owl">&#129418;</span>
      <span class="header-name">FinOwl</span>
    </div>
    <div class="body">
      ${title ? `<h2>${title}</h2>` : ''}
      ${subtitle ? `<p class="sub">${subtitle}</p>` : ''}
      ${content}
      <div class="divider"></div>
      <div class="footer">
        <p>Sent by <a href="https://finowl.co.uk">FinOwl</a></p>
        <p style="margin-top:4px">Autonomous bookkeeping for UK sole traders &amp; small business</p>
      </div>
    </div>
  </div>
</body>
</html>`;
}

module.exports = {
  sendEmail,
  sendAuthEmail,
  sendInvoiceEmail,
  sendInviteEmail,
  sendWelcomeEmail,
  sendPasswordResetEmail,
  sendSmtpEmail,
  sendPolsiaEmail,
  wrapHtml,
};