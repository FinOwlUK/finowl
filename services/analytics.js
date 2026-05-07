/**
 * Analytics service — handles server-side analytics data storage.
 * Client-side uses GA4 (gtag.js) for actual tracking.
 * This module stores raw events + page views for the /api/analytics endpoint.
 */

const pool = globalThis.__finowlPool;

/**
 * Record a page view.
 */
async function recordPageView({ userId, sessionId, path, referrer, utmParams = {}, userAgent, ipAddress }) {
  await pool.query(
    `INSERT INTO page_views (user_id, session_id, path, referrer, utm_source, utm_medium, utm_campaign, utm_term, utm_content, user_agent, ip_address)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    [
      userId || null,
      sessionId || '',
      path || '',
      referrer || '',
      utmParams.utm_source || '',
      utmParams.utm_medium || '',
      utmParams.utm_campaign || '',
      utmParams.utm_term || '',
      utmParams.utm_content || '',
      userAgent || '',
      ipAddress || '',
    ]
  );
}

/**
 * Record a key analytics event.
 */
async function recordEvent({ userId, sessionId, eventName, properties = {}, utmParams = {}, userAgent, ipAddress }) {
  await pool.query(
    `INSERT INTO analytics_events (user_id, session_id, event_name, properties, utm_source, utm_medium, utm_campaign, user_agent, ip_address)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      userId || null,
      sessionId || '',
      eventName,
      Object.keys(properties).length > 0 ? JSON.stringify(properties) : null,
      utmParams.utm_source || '',
      utmParams.utm_medium || '',
      utmParams.utm_campaign || '',
      userAgent || '',
      ipAddress || '',
    ]
  );
}

/**
 * Get analytics summary for the dashboard API.
 * Returns totals + funnel data.
 */
async function getAnalyticsSummary({ startDate, endDate } = {}) {
  const since = startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  const until = endDate || new Date().toISOString().split('T')[0];

  const [pageViewsResult, eventsResult, usersResult, funnelResult] = await Promise.all([
    // Total page views in period
    pool.query(
      `SELECT COUNT(*) as total_page_views FROM page_views WHERE DATE(created_at) BETWEEN $1 AND $2`,
      [since, until]
    ),
    // Unique sessions
    pool.query(
      `SELECT COUNT(DISTINCT session_id) as unique_sessions FROM page_views WHERE DATE(created_at) BETWEEN $1 AND $2`,
      [since, until]
    ),
    // Unique users who have logged in
    pool.query(
      `SELECT COUNT(DISTINCT user_id) as unique_users
       FROM page_views
       WHERE user_id IS NOT NULL AND DATE(created_at) BETWEEN $1 AND $2`,
      [since, until]
    ),
    // Funnel: count each event type
    pool.query(
      `SELECT event_name, COUNT(*) as count
       FROM analytics_events
       WHERE DATE(created_at) BETWEEN $1 AND $2
       GROUP BY event_name
       ORDER BY count DESC`,
      [since, until]
    ),
  ]);

  // Conversion funnel: visits → signup → bank connect → receipt → VAT
  const funnel = funnelResult.rows.reduce((acc, row) => {
    acc[row.event_name] = parseInt(row.count, 10);
    return acc;
  }, {});

  // UTM source breakdown for page views
  const utmBreakdown = await pool.query(
    `SELECT utm_source, COUNT(*) as page_views, COUNT(DISTINCT session_id) as sessions
     FROM page_views
     WHERE DATE(created_at) BETWEEN $1 AND $2 AND utm_source != ''
     GROUP BY utm_source
     ORDER BY page_views DESC`,
    [since, until]
  );

  // Daily trend (last 14 days)
  const dailyTrend = await pool.query(
    `SELECT DATE(created_at) as date, COUNT(*) as page_views
     FROM page_views
     WHERE created_at >= NOW() - INTERVAL '14 days'
     GROUP BY DATE(created_at)
     ORDER BY date ASC`
  );

  return {
    period: { since, until },
    total_page_views: parseInt(pageViewsResult.rows[0].total_page_views, 10),
    unique_sessions: parseInt(eventsResult.rows[0].unique_sessions, 10),
    unique_users: parseInt(usersResult.rows[0].unique_users, 10),
    funnel,
    utm_breakdown: utmBreakdown.rows,
    daily_trend: dailyTrend.rows,
  };
}

module.exports = {
  recordPageView,
  recordEvent,
  getAnalyticsSummary,
};