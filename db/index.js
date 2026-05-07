/**
 * Database connection pool.
 * Re-exports the shared pool from globalThis (set by server.js).
 */
const pool = globalThis.__finowlPool;
module.exports = { pool };