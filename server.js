// Local / traditional-host entrypoint (npm start, npm run dev). Not used on
// Vercel - see api/index.js for the serverless entrypoint, which reuses the
// same Express app from app.js but skips app.listen (Vercel manages the
// HTTP server itself).
const app = require('./app');
const { applySchemaIfNeeded } = require('./db/migrate');
const logger = require('./utils/logger');

const PORT = process.env.PORT || 4000;

applySchemaIfNeeded(logger)
  .catch((err) => {
    logger.error('Database migration failed - starting anyway; the API will likely fail until this is fixed.', err);
  })
  .finally(() => {
    app.listen(PORT, () => {
      logger.info(`LinkShield API listening on port ${PORT}`);
    });
  });

module.exports = app;
