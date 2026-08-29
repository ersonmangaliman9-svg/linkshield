const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

/**
 * Applies db/schema.sql once. Safe to call on every server boot: it checks
 * whether the `users` table already exists and skips if so, so a free-tier
 * host that restarts the process on every deploy (or wakes it from sleep)
 * won't try to re-run CREATE TABLE and crash on "already exists".
 */
async function applySchemaIfNeeded(logger) {
  const log = logger || console;
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : false,
  });

  await client.connect();
  try {
    const { rows } = await client.query("SELECT to_regclass('public.users') AS exists");
    if (rows[0] && rows[0].exists) {
      log.info ? log.info('[migrate] schema already present - skipping') : log.log('[migrate] schema already present - skipping');
      return;
    }
    log.info ? log.info('[migrate] applying db/schema.sql ...') : log.log('[migrate] applying db/schema.sql ...');
    const sql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
    await client.query(sql);
    log.info ? log.info('[migrate] done') : log.log('[migrate] done');
  } finally {
    await client.end();
  }
}

module.exports = { applySchemaIfNeeded };

// Allow `node db/migrate.js` for manual/CLI use too.
if (require.main === module) {
  require('dotenv').config();
  applySchemaIfNeeded()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('[migrate] failed:', err);
      process.exit(1);
    });
}
