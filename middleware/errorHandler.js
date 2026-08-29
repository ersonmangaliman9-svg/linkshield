const { validationResult } = require('express-validator');
const logger = require('../utils/logger');

/** Run after express-validator checks; returns 422 with details on failure. */
function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ error: 'Validation failed', details: errors.array() });
  }
  next();
}

/** Central error handler - keep messages generic in production. */
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  logger.error(err.message, { stack: err.stack, path: req.path });

  const isProd = process.env.NODE_ENV === 'production';
  const status = err.status || 500;
  res.status(status).json({
    error: isProd && status === 500 ? 'Internal server error' : err.message,
  });
}

function notFound(req, res) {
  res.status(404).json({ error: 'Route not found' });
}

module.exports = { validate, errorHandler, notFound };
