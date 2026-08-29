const router = require('express').Router();
const { body } = require('express-validator');
const db = require('../config/db');
const { validate } = require('../middleware/errorHandler');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);

router.patch(
  '/profile',
  [body('fullName').optional().trim().isLength({ max: 255 }), body('avatarUrl').optional().isURL()],
  validate,
  async (req, res, next) => {
    try {
      const { fullName, avatarUrl } = req.body;
      const { rows } = await db.query(
        `UPDATE users SET full_name = COALESCE($1, full_name), avatar_url = COALESCE($2, avatar_url), updated_at = now()
         WHERE id = $3 RETURNING id, email, full_name, avatar_url`,
        [fullName, avatarUrl, req.user.id]
      );
      res.json(rows[0]);
    } catch (err) { next(err); }
  }
);

router.get('/settings', async (req, res, next) => {
  try {
    const { rows } = await db.query('SELECT * FROM settings WHERE user_id = $1', [req.user.id]);
    res.json(rows[0] || {});
  } catch (err) { next(err); }
});

router.patch(
  '/settings',
  [
    body('theme').optional().isIn(['light', 'dark', 'system']),
    body('pushEnabled').optional().isBoolean(),
    body('emailAlerts').optional().isBoolean(),
    body('autoScanSharedLinks').optional().isBoolean(),
  ],
  validate,
  async (req, res, next) => {
    try {
      const { theme, pushEnabled, emailAlerts, autoScanSharedLinks, language } = req.body;
      const { rows } = await db.query(
        `UPDATE settings SET
           theme = COALESCE($1, theme),
           push_enabled = COALESCE($2, push_enabled),
           email_alerts = COALESCE($3, email_alerts),
           auto_scan_shared_links = COALESCE($4, auto_scan_shared_links),
           language = COALESCE($5, language),
           updated_at = now()
         WHERE user_id = $6 RETURNING *`,
        [theme, pushEnabled, emailAlerts, autoScanSharedLinks, language, req.user.id]
      );
      res.json(rows[0]);
    } catch (err) { next(err); }
  }
);

router.delete('/account', async (req, res, next) => {
  try {
    await db.query('UPDATE users SET is_active = FALSE WHERE id = $1', [req.user.id]);
    res.json({ success: true });
  } catch (err) { next(err); }
});

module.exports = router;
