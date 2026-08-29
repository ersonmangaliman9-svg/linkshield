const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/db');
const logger = require('../utils/logger');

const ACCESS_EXPIRES = process.env.JWT_ACCESS_EXPIRES || '15m';
const REFRESH_EXPIRES = process.env.JWT_REFRESH_EXPIRES || '30d';

function signTokens(user) {
  const accessToken = jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_ACCESS_SECRET, {
    expiresIn: ACCESS_EXPIRES,
  });
  const refreshToken = jwt.sign({ sub: user.id, type: 'refresh' }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: REFRESH_EXPIRES,
  });
  return { accessToken, refreshToken };
}

async function register(req, res, next) {
  try {
    const { email, password, fullName } = req.body;

    const existing = await db.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const { rows } = await db.query(
      `INSERT INTO users (email, password_hash, full_name)
       VALUES ($1, $2, $3) RETURNING id, email, full_name, role, created_at`,
      [email.toLowerCase(), passwordHash, fullName || null]
    );
    const user = rows[0];

    // Default free plan assignment
    const plan = await db.query("SELECT id FROM subscription_plans WHERE code = 'free'");
    if (plan.rows[0]) {
      await db.query(
        `INSERT INTO subscriptions (user_id, plan_id, status, current_period_end)
         VALUES ($1, $2, 'active', now() + interval '30 days')`,
        [user.id, plan.rows[0].id]
      );
    }
    await db.query('INSERT INTO settings (user_id) VALUES ($1)', [user.id]);

    const tokens = signTokens(user);
    res.status(201).json({ user, ...tokens });
  } catch (err) {
    next(err);
  }
}

async function login(req, res, next) {
  try {
    const { email, password } = req.body;
    const { rows } = await db.query(
      'SELECT id, email, full_name, role, password_hash, is_active FROM users WHERE email = $1',
      [email.toLowerCase()]
    );
    const user = rows[0];

    // Constant-shape response to avoid user-enumeration timing differences
    const dummyHash = '$2b$12$C6UzMDM.H6dfI/f/IKcEeO2yUUwqYh1yWuJ0PKuVIqOyMDCUgtR8m';
    const match = await bcrypt.compare(password, user ? user.password_hash : dummyHash);

    if (!user || !match || !user.is_active) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    await db.query('UPDATE users SET last_login_at = now() WHERE id = $1', [user.id]);
    await db.query(
      `INSERT INTO audit_logs (actor_id, action, ip_address, user_agent) VALUES ($1, 'user.login', $2, $3)`,
      [user.id, req.ip, req.headers['user-agent'] || null]
    );

    const tokens = signTokens(user);
    delete user.password_hash;
    res.json({ user, ...tokens });
  } catch (err) {
    next(err);
  }
}

async function refresh(req, res, next) {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'Missing refresh token' });

    const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const { rows } = await db.query('SELECT id, role, is_active FROM users WHERE id = $1', [payload.sub]);
    const user = rows[0];
    if (!user || !user.is_active) return res.status(401).json({ error: 'Account not found or disabled' });

    const tokens = signTokens(user);
    res.json(tokens);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
}

async function me(req, res, next) {
  try {
    const { rows } = await db.query(
      `SELECT u.id, u.email, u.full_name, u.role, u.avatar_url, u.created_at,
              u.scans_used_this_period, u.period_reset_at,
              s.status AS subscription_status, p.code AS plan_code, p.name AS plan_name, p.scan_limit
       FROM users u
       LEFT JOIN subscriptions s ON s.user_id = u.id AND s.status = 'active'
       LEFT JOIN subscription_plans p ON p.id = s.plan_id
       WHERE u.id = $1`,
      [req.user.id]
    );
    res.json({ user: rows[0] });
  } catch (err) {
    next(err);
  }
}

async function logout(req, res) {
  // Stateless JWT logout: client discards tokens. For hard revocation, maintain
  // a refresh-token denylist table keyed by jti - omitted here for MVP simplicity.
  res.json({ success: true });
}

module.exports = { register, login, refresh, me, logout };
