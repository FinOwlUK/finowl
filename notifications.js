/**
 * FinOwl Notification Service
 * Handles: VAT deadline reminders, weekly summaries, unusual transaction alerts
 * Uses: email.js utility (which routes through Polsia email proxy)
 */

// ─── Email utility (delegates to email.js) ──────────────────────────────────
const { sendEmail } = require('./email');

// ─── Email Templates ─────────────────────────────────────────────────────────

function emailWrapper(content) {
  return `
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
    h2 { font-size:22px; font-weight:700; margin-bottom:6px; }
    p.sub { color:#6b7280; font-size:14px; margin-bottom:20px; }
    .divider { height:1px; background:#e5e2db; margin:20px 0; }
    .stat-row { display:flex; justify-content:space-between; padding:10px 0; font-size:14px; border-bottom:1px solid #f0eee9; }
    .stat-row:last-child { border-bottom:none; }
    .stat-label { color:#6b7280; }
    .stat-val { font-weight:600; }
    .val-green { color:#2d6a4f; }
    .val-red { color:#c0392b; }
    .val-amber { color:#d4920b; }
    .alert-box { background:#fff8e6; border:1px solid #f5dfa3; border-radius:10px; padding:16px; margin:16px 0; }
    .alert-box .alert-icon { font-size:20px; margin-bottom:6px; }
    .alert-box p { font-size:14px; line-height:1.6; }
    .deadline-box { background:#fef2f2; border:1px solid #fecaca; border-radius:10px; padding:16px; margin:16px 0; }
    .deadline-box.warn { background:#fff8e6; border-color:#f5dfa3; }
    .deadline-box .days-badge { display:inline-block; background:#dc2626; color:#fff; border-radius:6px; padding:2px 10px; font-size:12px; font-weight:700; margin-bottom:8px; }
    .deadline-box.warn .days-badge { background:#d4920b; }
    .cta-btn { display:inline-block; background:#d4920b; color:#fff; text-decoration:none; padding:12px 24px; border-radius:8px; font-weight:600; font-size:14px; margin-top:20px; }
    .footer { margin-top:20px; text-align:center; font-size:12px; color:#9ca3af; }
    .footer a { color:#d4920b; text-decoration:none; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <span class="header-owl">🦉</span>
      <span class="header-name">FinOwl</span>
    </div>
    <div class="body">
      ${content}
      <div class="footer">
        <p>You're receiving this from <a href="https://finowl.co.uk">FinOwl</a> because you have email notifications enabled.</p>
        <p style="margin-top:4px">To adjust your preferences, visit <a href="https://finowl.co.uk/dashboard">dashboard → Notifications</a>.</p>
      </div>
    </div>
  </div>
</body>
</html>`;
}

// ─── Notification: VAT Deadline Reminder ─────────────────────────────────────

function getVATDeadlines(periodStartMonth, referenceDate) {
  // UK VAT returns: due 1 month + 7 days after period end
  // Quarter periods defined by period_start_month offset
  const pStart = ((periodStartMonth - 1 + 12) % 12); // 0-indexed month
  const deadlines = [];
  const year = referenceDate.getFullYear();

  for (let i = -1; i <= 3; i++) {
    // Each quarter is 3 months from the start month
    const periodEndMonth = (pStart + 3 + i * 3) % 12; // 0-indexed end month of quarter
    const periodEndYear  = year + Math.floor((pStart + 3 + i * 3) / 12);
    // Last day of that month
    const periodEnd = new Date(periodEndYear, periodEndMonth + 1, 0);
    // Deadline: +1 month +7 days
    const deadline = new Date(periodEnd);
    deadline.setMonth(deadline.getMonth() + 1);
    deadline.setDate(deadline.getDate() + 7);

    // Quarter label
    const qMonth = (periodEnd.getMonth() + 1); // 1-indexed
    const qYear  = periodEnd.getFullYear();
    const qNum   = Math.ceil(qMonth / 3);
    const label  = `Q${qNum} ${qYear} VAT Return`;

    deadlines.push({ deadline, label, periodEnd });
  }
  return deadlines;
}

function vatDeadlineEmailHtml(name, label, deadline, daysLeft) {
  const dateStr = deadline.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
  const urgency = daysLeft <= 7 ? 'deadline-box' : 'deadline-box warn';
  const badgeText = daysLeft <= 7 ? `${daysLeft} days left` : `${daysLeft} days away`;

  return emailWrapper(`
    <h2>📅 VAT Return Reminder</h2>
    <p class="sub">Your ${label} deadline is approaching</p>

    <div class="${urgency}">
      <div class="days-badge">${badgeText}</div>
      <p><strong>${label}</strong> is due on <strong>${dateStr}</strong>.</p>
      <p style="margin-top:6px;font-size:13px;color:#6b7280">Log into FinOwl to check your VAT position and make sure everything is categorised before you file.</p>
    </div>

    <p style="font-size:14px;margin-top:12px">
      💡 <strong>HMRC tip:</strong> File your VAT return and pay any VAT owed by ${dateStr} to avoid surcharges.
      Direct Debit payments are collected 3 working days after the filing deadline.
    </p>

    <a href="https://finowl.co.uk/dashboard" class="cta-btn">View VAT Summary →</a>
  `);
}

// ─── Notification: Weekly Summary ────────────────────────────────────────────

function weeklySummaryEmailHtml(name, stats) {
  const fmtGBP = v => {
    const abs = Math.abs(v);
    const sign = v < 0 ? '-' : '';
    return `${sign}£${abs.toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  };

  const vatColor = stats.vatPosition >= 0 ? 'val-red' : 'val-green';
  const vatLabel = stats.vatPosition >= 0 ? 'owed to HMRC' : 'reclaimable';
  const netColor = stats.netPosition >= 0 ? 'val-green' : 'val-red';

  const weekStart = stats.weekStart.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
  const weekEnd   = stats.weekEnd.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });

  return emailWrapper(`
    <h2>📬 Your Weekly FinOwl Summary</h2>
    <p class="sub">${weekStart} – ${weekEnd}</p>

    <div class="stat-row">
      <span class="stat-label">💰 Income this week</span>
      <span class="stat-val val-green">${fmtGBP(stats.income)}</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">💸 Expenses this week</span>
      <span class="stat-val val-red">${fmtGBP(stats.expenses)}</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">📈 Net position (week)</span>
      <span class="stat-val ${netColor}">${fmtGBP(stats.netPosition)}</span>
    </div>
    <div class="divider"></div>
    <div class="stat-row">
      <span class="stat-label">🏛️ VAT position (this quarter)</span>
      <span class="stat-val ${vatColor}">${fmtGBP(stats.vatPosition)} ${vatLabel}</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">🏷️ Uncategorised transactions</span>
      <span class="stat-val ${stats.uncategorised > 0 ? 'val-amber' : ''}">${stats.uncategorised}</span>
    </div>

    ${stats.uncategorised > 0 ? `
    <div class="alert-box" style="margin-top:16px">
      <div class="alert-icon">⚡</div>
      <p>You have <strong>${stats.uncategorised} uncategorised transactions</strong>. Categorising them keeps your VAT and tax calculations accurate.</p>
    </div>` : ''}

    <a href="https://finowl.co.uk/dashboard" class="cta-btn">Open FinOwl →</a>
  `);
}

// ─── Notification: Unusual Transaction Alert ──────────────────────────────────

function unusualTxEmailHtml(name, tx, threshold) {
  const amtStr = (tx.amount >= 0 ? '+' : '') + '£' + Math.abs(tx.amount).toLocaleString('en-GB', { minimumFractionDigits: 2 });
  const dateStr = new Date(tx.date).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
  const merchant = tx.merchant_name || tx.description || 'Unknown';
  const category = tx.category_name || 'Uncategorised';

  return emailWrapper(`
    <h2>⚠️ Unusual Transaction Detected</h2>
    <p class="sub">A large transaction was added to your account</p>

    <div class="alert-box">
      <p style="font-size:15px;font-weight:600;margin-bottom:8px">${amtStr} — ${merchant}</p>
      <div class="stat-row"><span class="stat-label">Date</span><span class="stat-val">${dateStr}</span></div>
      <div class="stat-row"><span class="stat-label">Category</span><span class="stat-val">${category}</span></div>
      <div class="stat-row"><span class="stat-label">Description</span><span class="stat-val" style="font-size:13px">${tx.description || '—'}</span></div>
    </div>

    <p style="font-size:14px;margin-top:4px;color:#6b7280">
      This transaction is over your £${threshold.toLocaleString('en-GB')} alert threshold.
      Please check it looks correct — if the category is wrong, you can update it in FinOwl.
    </p>

    <a href="https://finowl.co.uk/dashboard" class="cta-btn">Review Transaction →</a>
  `);
}

// ─── Deduplication Check ──────────────────────────────────────────────────────

async function alreadySent(pool, userId, type, referenceKey) {
  const res = await pool.query(
    `SELECT id FROM notification_log WHERE user_id = $1 AND type = $2 AND reference_key = $3`,
    [userId, type, referenceKey]
  );
  return res.rows.length > 0;
}

async function markSent(pool, userId, type, referenceKey) {
  await pool.query(
    `INSERT INTO notification_log (user_id, type, reference_key) VALUES ($1, $2, $3)`,
    [userId, type, referenceKey]
  );
}

// ─── Main Scheduler Handlers ─────────────────────────────────────────────────

/**
 * Send VAT deadline reminders to all eligible users.
 * Sends at 30, 14, 7 days before deadline.
 */
async function runVATDeadlineReminders(pool) {
  console.log('[Notifications] Running VAT deadline reminders...');
  const now = new Date();

  try {
    const users = await pool.query(`
      SELECT u.id, u.email, u.name,
             COALESCE(ns.vat_deadline_reminders, true) AS vat_deadline_reminders,
             COALESCE(vs.period_start_month, 4) AS period_start_month
      FROM users u
      LEFT JOIN notification_settings ns ON ns.user_id = u.id
      LEFT JOIN vat_settings vs ON vs.user_id = u.id
      WHERE u.subscribed_at IS NOT NULL
    `);

    for (const user of users.rows) {
      if (!user.vat_deadline_reminders) continue;

      const deadlines = getVATDeadlines(user.period_start_month, now);

      for (const { deadline, label } of deadlines) {
        const daysLeft = Math.round((deadline - now) / (1000 * 60 * 60 * 24));

        for (const triggerDay of [30, 14, 7]) {
          if (daysLeft <= triggerDay && daysLeft > triggerDay - 2) {
            const refKey = `vat-${label}-d${triggerDay}`;
            if (await alreadySent(pool, user.id, 'vat_reminder', refKey)) continue;

            try {
              await sendEmail({
                to: user.email,
                subject: `📅 ${label} due in ${daysLeft} days`,
                htmlBody: vatDeadlineEmailHtml(user.name, label, deadline, daysLeft),
              });
              await markSent(pool, user.id, 'vat_reminder', refKey);
              console.log(`[Notifications] Sent VAT reminder to ${user.email}: ${refKey}`);
            } catch (e) {
              console.error(`[Notifications] Failed VAT reminder to ${user.email}:`, e.message);
            }
          }
        }
      }
    }
  } catch (e) {
    console.error('[Notifications] VAT reminder error:', e.message);
  }
}

/**
 * Send weekly summary emails (runs on Monday mornings).
 */
async function runWeeklySummaries(pool) {
  console.log('[Notifications] Running weekly summaries...');
  const now = new Date();

  // Only run on Mondays (day 1)
  if (now.getDay() !== 1) {
    console.log('[Notifications] Not Monday — skipping weekly summaries');
    return;
  }

  // Week: Mon–Sun last week
  const weekEnd   = new Date(now);
  weekEnd.setDate(weekEnd.getDate() - 1);
  weekEnd.setHours(23, 59, 59, 999);
  const weekStart = new Date(weekEnd);
  weekStart.setDate(weekStart.getDate() - 6);
  weekStart.setHours(0, 0, 0, 0);

  const weekKey = weekStart.toISOString().slice(0, 10);

  try {
    const users = await pool.query(`
      SELECT u.id, u.email, u.name,
             COALESCE(ns.weekly_summary, true) AS weekly_summary,
             COALESCE(vs.period_start_month, 4) AS period_start_month
      FROM users u
      LEFT JOIN notification_settings ns ON ns.user_id = u.id
      LEFT JOIN vat_settings vs ON vs.user_id = u.id
      WHERE u.subscribed_at IS NOT NULL
    `);

    for (const user of users.rows) {
      if (!user.weekly_summary) continue;
      const refKey = `weekly-${weekKey}`;
      if (await alreadySent(pool, user.id, 'weekly_summary', refKey)) continue;

      try {
        // Weekly transactions
        const txRes = await pool.query(`
          SELECT
            SUM(CASE WHEN c.is_income = true THEN ABS(t.amount) ELSE 0 END) AS income,
            SUM(CASE WHEN c.is_income = false OR c.is_income IS NULL THEN ABS(t.amount) ELSE 0 END) AS expenses,
            COUNT(*) FILTER (WHERE t.category_id IS NULL AND t.is_manually_categorised = false) AS uncategorised
          FROM transactions t
          LEFT JOIN categories c ON t.category_id = c.id
          WHERE t.user_id = $1 AND t.date BETWEEN $2 AND $3
        `, [user.id, weekStart.toISOString().slice(0, 10), weekEnd.toISOString().slice(0, 10)]);

        const tx = txRes.rows[0];
        const income     = parseFloat(tx.income || 0);
        const expenses   = parseFloat(tx.expenses || 0);
        const netPosition = income - expenses;

        // VAT position for current quarter
        const quarterMonth = Math.ceil((now.getMonth() + 1) / 3) * 3;
        const quarterYear  = now.getFullYear();
        const qStart = new Date(quarterYear, quarterMonth - 3, 1).toISOString().slice(0, 10);
        const qEnd   = new Date(quarterYear, quarterMonth, 0).toISOString().slice(0, 10);

        const vatRes = await pool.query(`
          SELECT
            SUM(CASE WHEN c.is_income = true AND c.vat_rate IS NOT NULL THEN
              t.amount - (t.amount / (1 + c.vat_rate::decimal / 100)) ELSE 0 END) AS output_vat,
            SUM(CASE WHEN c.is_income = false AND c.vat_rate IS NOT NULL THEN
              ABS(t.amount) - (ABS(t.amount) / (1 + c.vat_rate::decimal / 100)) ELSE 0 END) AS input_vat
          FROM transactions t
          LEFT JOIN categories c ON t.category_id = c.id
          WHERE t.user_id = $1 AND t.date BETWEEN $2 AND $3 AND c.vat_rate IS NOT NULL
        `, [user.id, qStart, qEnd]);

        const vat = vatRes.rows[0];
        const vatPosition = parseFloat(vat.output_vat || 0) - parseFloat(vat.input_vat || 0);

        // Uncategorised count (total, not just this week)
        const uncatRes = await pool.query(
          `SELECT COUNT(*) AS n FROM transactions WHERE user_id = $1 AND category_id IS NULL AND is_manually_categorised = false`,
          [user.id]
        );
        const uncategorised = parseInt(uncatRes.rows[0].n || 0);

        const stats = { income, expenses, netPosition, vatPosition, uncategorised, weekStart, weekEnd };

        await sendEmail({
          to: user.email,
          subject: `📬 Your FinOwl weekly summary (${weekStart.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })} – ${weekEnd.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })})`,
          htmlBody: weeklySummaryEmailHtml(user.name, stats),
        });
        await markSent(pool, user.id, 'weekly_summary', refKey);
        console.log(`[Notifications] Sent weekly summary to ${user.email}`);
      } catch (e) {
        console.error(`[Notifications] Weekly summary failed for ${user.email}:`, e.message);
      }
    }
  } catch (e) {
    console.error('[Notifications] Weekly summary error:', e.message);
  }
}

/**
 * Send unusual transaction alert for a specific transaction.
 * Called when a transaction is imported/categorised.
 */
async function sendUnusualTransactionAlert(pool, userId, transaction) {
  try {
    // Get user notification settings
    const settingsRes = await pool.query(`
      SELECT u.email, u.name,
             COALESCE(ns.unusual_transaction_alerts, true) AS alerts_on,
             COALESCE(ns.unusual_tx_threshold, 500) AS threshold
      FROM users u
      LEFT JOIN notification_settings ns ON ns.user_id = u.id
      WHERE u.id = $1
    `, [userId]);

    if (!settingsRes.rows[0]) return;
    const { email, name, alerts_on, threshold } = settingsRes.rows[0];

    if (!alerts_on) return;

    const amount = Math.abs(parseFloat(transaction.amount));
    if (amount < parseFloat(threshold)) return;

    // Only alert for expenses (outgoing transactions)
    if (parseFloat(transaction.amount) > 0) return; // positive = income, skip

    const refKey = `unusual-tx-${transaction.id}`;
    if (await alreadySent(pool, userId, 'unusual_tx', refKey)) return;

    await sendEmail({
      to: email,
      subject: `⚠️ Large transaction: £${amount.toLocaleString('en-GB', { minimumFractionDigits: 2 })} — ${transaction.merchant_name || transaction.description || 'Unknown'}`,
      htmlBody: unusualTxEmailHtml(name, transaction, threshold),
    });
    await markSent(pool, userId, 'unusual_tx', refKey);
    console.log(`[Notifications] Sent unusual tx alert to ${email}: tx#${transaction.id} £${amount}`);
  } catch (e) {
    console.error('[Notifications] Unusual tx alert error:', e.message);
  }
}

// ─── Invoice Reminder Email Template ─────────────────────

function invoiceReminderEmailHtml({ invoiceNumber, clientName, ownerName, amount, dueDate, viewLink, dayType }) {
  const fmtGBP = (n) => `£${parseFloat(n || 0).toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  const dueDateStr = dueDate ? new Date(dueDate).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }) : '—';

  let heading, subtext, urgencyStyle;

  if (dayType === 0) {
    heading  = `📅 Payment Due Today — ${invoiceNumber}`;
    subtext  = `Just a friendly reminder that invoice ${invoiceNumber} is due today.`;
    urgencyStyle = 'background:#fff8e6;border:1px solid #f5dfa3';
  } else {
    const days = Math.abs(dayType);
    heading  = `⏰ Invoice ${invoiceNumber} — ${days} Day${days === 1 ? '' : 's'} Overdue`;
    subtext  = `Invoice ${invoiceNumber} was due on ${dueDateStr} and is now ${days} day${days === 1 ? '' : 's'} overdue.`;
    urgencyStyle = dayType >= 14
      ? 'background:#fee2e2;border:1px solid #fecaca'
      : 'background:#fff8e6;border:1px solid #f5dfa3';
  }

  return emailWrapper(`
    <h2>${heading}</h2>
    <p class="sub">From ${ownerName || 'your supplier'}</p>

    <div style="${urgencyStyle};border-radius:10px;padding:16px;margin:16px 0">
      <p style="font-size:15px;line-height:1.6">${subtext}</p>
      <div class="stat-row" style="margin-top:10px">
        <span class="stat-label">Invoice number</span>
        <span class="stat-val">${invoiceNumber}</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Amount due</span>
        <span class="stat-val val-red">${fmtGBP(amount)}</span>
      </div>
      <div class="stat-row">
        <span class="stat-label">Due date</span>
        <span class="stat-val">${dueDateStr}</span>
      </div>
    </div>

    <p style="font-size:14px;color:#6b7280;margin-top:8px;line-height:1.6">
      If you have already arranged payment, please ignore this reminder. If you have any questions,
      please don't hesitate to get in touch.
    </p>

    <a href="${viewLink}" class="cta-btn">View Invoice →</a>

    <div class="divider"></div>
    <p style="font-size:12px;color:#9ca3af;margin-top:8px">
      This is an automated reminder from FinOwl on behalf of ${ownerName || 'your supplier'}.
      To view the invoice online, click the button above.
    </p>
  `);
}

// ─── Invoice Reminder Scheduler ──────────────────────────

/**
 * Send payment chase emails for overdue invoices.
 * Sends at: day 0 (due today), day 3, 7, 14 overdue.
 * Emails go to the CLIENT (client_email), not the user.
 * Stops if invoice is paid.
 */
async function runInvoiceReminders(pool) {
  console.log('[Notifications] Running invoice payment reminders...');
  const now = new Date();
  const todayStr = now.toISOString().slice(0, 10);

  try {
    // Auto-mark sent invoices as overdue first
    await pool.query(`
      UPDATE invoices SET status = 'overdue', updated_at = NOW()
       WHERE status = 'sent' AND due_date < $1
    `, [todayStr]);

    // Get global reminder settings per user, and all candidate invoices
    // Candidate = sent or overdue, has client_email, auto_reminders_enabled, not paid
    const invoices = await pool.query(`
      SELECT i.*,
             u.email AS owner_email,
             u.name  AS owner_name,
             COALESCE(ns.invoice_auto_reminders, true) AS global_reminders_on,
             COALESCE(ns.invoice_reminder_days, '[0,3,7,14]'::jsonb) AS reminder_days
        FROM invoices i
        JOIN users u ON i.user_id = u.id
        LEFT JOIN notification_settings ns ON ns.user_id = i.user_id
       WHERE i.status IN ('sent', 'overdue')
         AND i.client_email IS NOT NULL
         AND i.client_email != ''
         AND i.auto_reminders_enabled = true
         AND i.paid_at IS NULL
         AND i.due_date IS NOT NULL
    `);

    for (const inv of invoices.rows) {
      if (!inv.global_reminders_on) continue;

      const dueDate  = new Date(inv.due_date);
      const daysOverdue = Math.floor((now - dueDate) / (1000 * 60 * 60 * 24));
      // daysOverdue = 0 means today is the due date
      // daysOverdue > 0 means overdue

      let reminderDays;
      try {
        reminderDays = Array.isArray(inv.reminder_days)
          ? inv.reminder_days
          : JSON.parse(inv.reminder_days);
      } catch {
        reminderDays = [0, 3, 7, 14];
      }

      // Find which trigger day applies right now (allow 1-day window to catch any we might have missed)
      for (const triggerDay of reminderDays) {
        // triggerDay 0 = due today (daysOverdue = 0)
        // triggerDay 3 = 3 days overdue (daysOverdue = 3)
        if (daysOverdue !== triggerDay) continue;

        // Check if already sent
        const alreadySentRes = await pool.query(
          `SELECT id FROM invoice_reminder_log WHERE invoice_id = $1 AND reminder_day = $2`,
          [inv.id, triggerDay]
        );
        if (alreadySentRes.rows.length > 0) continue;

        const viewLink = `https://finowl.co.uk/i/${inv.view_token}`;
        const subject  = triggerDay === 0
          ? `Reminder: ${inv.invoice_number} is due today`
          : `Payment overdue: ${inv.invoice_number} (${triggerDay} days)`;

        try {
          await sendEmail({
            to: inv.client_email,
            subject,
            htmlBody: invoiceReminderEmailHtml({
              invoiceNumber: inv.invoice_number,
              clientName:    inv.client_name,
              ownerName:     inv.owner_name || inv.owner_email,
              amount:        inv.total,
              dueDate:       inv.due_date,
              viewLink,
              dayType:       triggerDay,
            }),
          });

          // Log that we sent it
          await pool.query(
            `INSERT INTO invoice_reminder_log (invoice_id, reminder_day, client_email)
             VALUES ($1, $2, $3)`,
            [inv.id, triggerDay, inv.client_email]
          );

          console.log(`[Notifications] Invoice reminder sent: ${inv.invoice_number} day-${triggerDay} → ${inv.client_email}`);
        } catch (e) {
          console.error(`[Notifications] Invoice reminder failed: ${inv.invoice_number} day-${triggerDay}:`, e.message);
        }
      }
    }
  } catch (e) {
    console.error('[Notifications] Invoice reminders error:', e.message);
  }
}

/**
 * Main scheduler — runs every hour.
 */
function startNotificationScheduler(pool) {
  console.log('[Notifications] Scheduler started');

  async function runChecks() {
    await runVATDeadlineReminders(pool);
    await runWeeklySummaries(pool);
    await runInvoiceReminders(pool);
  }

  // Run once at startup (small delay to let DB warm up)
  setTimeout(runChecks, 30 * 1000);

  // Then every hour
  setInterval(runChecks, 60 * 60 * 1000);
}

module.exports = {
  startNotificationScheduler,
  sendUnusualTransactionAlert,
  runVATDeadlineReminders,
  runWeeklySummaries,
  runInvoiceReminders,
};
