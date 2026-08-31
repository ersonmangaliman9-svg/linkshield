// Vercel serverless entrypoint. Vercel builds every file under /api as its
// own function; this one wraps the whole Express app (see app.js) so all
// routes are handled by a single function, matching server.js's behavior.
//
// Schema migration runs lazily on cold start (once per warm container, not
// per-request) rather than blocking app.listen like the traditional
// server.js does - there is no app.listen here, Vercel's runtime calls this
// module's exported handler directly for each request.
const app = require('../app');
const { applySchemaIfNeeded } = require('../db/migrate');
const logger = require('../utils/logger');

let migrationPromise = null;

module.exports = (req, res) => {
  if (!migrationPromise) {
    migrationPromise = applySchemaIfNeeded(logger).catch((err) => {
      logger.error('Database migration failed on cold start - requests will likely fail until this is fixed.', err);
    });
  }
  // Don't block the request on the migration check after the first cold
  // start; only the very first invocation on a fresh container waits for it.
  migrationPromise.then(() => app(req, res)).catch(() => app(req, res));
};
