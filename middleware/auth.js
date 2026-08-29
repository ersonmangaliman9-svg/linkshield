const jwt = require('jsonwebtoken');
const db = require('../config/db');

/**
 * Verifies the access token sent in the Authorization header (Bearer <token>).
 * Attaches req.user = { id, role, email } on success.
 */
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) {
      return res.status(401).json({ error: 'Missing access token' });
    }

    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

    const { rows } = await db.query(
      'SELECT id, email, role, is_active FROM users WHERE id = $1',
      [payload.sub]
    );
    const user = rows[0];
    if (!user || !user.is_active) {
      return res.status(401).json({ error: 'Account not found or disabled' });
    }

    req.user = { id: user.id, email: user.email, role: user.role };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/** Restrict a route to admin/support roles. Use after requireAuth. */
function requireAdmin(req, res, next) {
  if (!req.user || !['admin', 'support'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

module.exports = { requireAuth, requireAdmin };
