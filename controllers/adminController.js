const db = require('../config/db');
const path = require('path');
const { getPaymentProofSignedUrl } = require('../services/paymentProofStorageService');

// ---------- Admin bootstrap ----------
// Promotes the CALLING (already logged-in) account to admin, but only if:
//   1. ADMIN_BOOTSTRAP_SECRET is set in the environment (unset = feature is
//      fully disabled, so it does nothing on a normal production deploy), and
//   2. the request supplies that exact secret, and
//   3. no admin/support account exists yet (one-time use).
// This exists so the very first admin can be created on a host with no shell
// access (e.g. a free Render web service) - after using it once, remove
// ADMIN_BOOTSTRAP_SECRET from your environment to close this off again.
async function bootstrapSelf(req, res, next) {
  try {
    const configuredSecret = process.env.ADMIN_BOOTSTRAP_SECRET;
    if (!configuredSecret) {
      return res.status(403).json({ error: 'Admin bootstrap is disabled. Set ADMIN_BOOTSTRAP_SECRET to enable it.' });
    }

    const provided = (req.body && req.body.secret) || req.headers['x-admin-bootstrap-secret'];
    if (!provided || provided !== configuredSecret) {
      return res.status(403).json({ error: 'Incorrect bootstrap secret.' });
    }

    const { rows: existingAdmins } = await db.query(
      "SELECT id FROM users WHERE role IN ('admin', 'support') LIMIT 1"
    );
    if (existingAdmins[0]) {
      return res.status(409).json({
        error: 'An admin account already exists. Bootstrap only works once - remove ADMIN_BOOTSTRAP_SECRET from your environment.',
      });
    }

    const { rows } = await db.query(
      `UPDATE users SET role = 'admin', updated_at = now() WHERE id = $1 RETURNING id, email, role`,
      [req.user.id]
    );
    res.json({ user: rows[0] });
  } catch (err) { next(err); }
}

// ---------- Users ----------
async function listUsers(req, res, next) {
  try {
    const { q, page = 1, pageSize = 25 } = req.query;
    const params = [];
    let where = '';
    if (q) { params.push(`%${q}%`); where = `WHERE email ILIKE $${params.length} OR full_name ILIKE $${params.length}`; }
    params.push(Number(pageSize), (Number(page) - 1) * Number(pageSize));

    const { rows } = await db.query(
      `SELECT id, email, full_name, role, is_active, is_verified, created_at, last_login_at
       FROM users ${where} ORDER BY created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );
    res.json({ items: rows });
  } catch (err) { next(err); }
}

async function updateUserStatus(req, res, next) {
  try {
    const { isActive, role } = req.body;
    const { rows } = await db.query(
      `UPDATE users SET is_active = COALESCE($1, is_active), role = COALESCE($2, role), updated_at = now()
       WHERE id = $3 RETURNING id, email, is_active, role`,
      [isActive, role, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });

    await db.query(
      `INSERT INTO audit_logs (actor_id, action, target_type, target_id, metadata)
       VALUES ($1, 'admin.user.update', 'user', $2, $3)`,
      [req.user.id, req.params.id, JSON.stringify(req.body)]
    );
    res.json(rows[0]);
  } catch (err) { next(err); }
}

// ---------- Subscription stats ----------
async function subscriptionStats(req, res, next) {
  try {
    const { rows } = await db.query(`
      SELECT p.code, p.name, COUNT(s.id) FILTER (WHERE s.status = 'active') AS active_subscribers,
             SUM(p.price_php) FILTER (WHERE s.status = 'active') AS mrr_php
      FROM subscription_plans p
      LEFT JOIN subscriptions s ON s.plan_id = p.id
      GROUP BY p.code, p.name
      ORDER BY p.price_php ASC
    `);
    res.json({ plans: rows });
  } catch (err) { next(err); }
}

// ---------- Scan stats ----------
async function scanStats(req, res, next) {
  try {
    const totals = await db.query(`
      SELECT scan_type, COUNT(*) AS total
      FROM scans GROUP BY scan_type
    `);
    const riskBreakdown = await db.query(`
      SELECT risk_level, COUNT(*) AS total FROM scan_results GROUP BY risk_level
    `);
    const dailyTrend = await db.query(`
      SELECT date_trunc('day', created_at) AS day, COUNT(*) AS total
      FROM scans WHERE created_at > now() - interval '30 days'
      GROUP BY day ORDER BY day ASC
    `);
    res.json({ byType: totals.rows, byRiskLevel: riskBreakdown.rows, dailyTrend: dailyTrend.rows });
  } catch (err) { next(err); }
}

// ---------- Threat domain database ----------
async function listThreatDomains(req, res, next) {
  try {
    const { rows } = await db.query('SELECT * FROM threat_domains ORDER BY created_at DESC LIMIT 200');
    res.json({ items: rows });
  } catch (err) { next(err); }
}

async function addThreatDomain(req, res, next) {
  try {
    const { domain, category, severity, notes } = req.body;
    const { rows } = await db.query(
      `INSERT INTO threat_domains (domain, category, severity, source, notes, added_by)
       VALUES ($1,$2,$3,'admin',$4,$5)
       ON CONFLICT (domain) DO UPDATE SET category = EXCLUDED.category, severity = EXCLUDED.severity,
         notes = EXCLUDED.notes, is_active = TRUE, updated_at = now()
       RETURNING *`,
      [domain.toLowerCase(), category || 'phishing', severity || 'dangerous', notes || null, req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
}

async function removeThreatDomain(req, res, next) {
  try {
    await db.query('UPDATE threat_domains SET is_active = FALSE WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { next(err); }
}

// ---------- Scam reports moderation ----------
async function listReports(req, res, next) {
  try {
    const { status } = req.query;
    const params = [];
    let where = '';
    if (status) { params.push(status); where = `WHERE status = $1`; }
    const { rows } = await db.query(`SELECT * FROM scam_reports ${where} ORDER BY created_at DESC`, params);
    res.json({ items: rows });
  } catch (err) { next(err); }
}

async function reviewReport(req, res, next) {
  try {
    const { status } = req.body; // reviewing | confirmed | rejected
    const { rows } = await db.query(
      `UPDATE scam_reports SET status = $1, reviewed_by = $2, reviewed_at = now() WHERE id = $3 RETURNING *`,
      [status, req.user.id, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Report not found' });

    // Confirmed link/domain reports feed directly into the threat database
    if (status === 'confirmed' && rows[0].report_type === 'link') {
      try {
        const { extractDomain } = require('../services/urlAnalysisService');
        const parsed = extractDomain(rows[0].reported_value);
        if (parsed) {
          await db.query(
            `INSERT INTO threat_domains (domain, category, severity, source, added_by)
             VALUES ($1, 'scam', 'dangerous', 'community', $2)
             ON CONFLICT (domain) DO UPDATE SET report_count = threat_domains.report_count + 1, is_active = TRUE`,
            [parsed.hostname, req.user.id]
          );
        }
      } catch (e) { /* non-fatal */ }
    }

    res.json(rows[0]);
  } catch (err) { next(err); }
}

// ---------- Analytics overview ----------
async function analyticsOverview(req, res, next) {
  try {
    const [users, scans, threats, reports] = await Promise.all([
      db.query('SELECT COUNT(*) FROM users'),
      db.query('SELECT COUNT(*) FROM scans'),
      db.query('SELECT COUNT(*) FROM threat_domains WHERE is_active = TRUE'),
      db.query("SELECT COUNT(*) FROM scam_reports WHERE status = 'pending'"),
    ]);
    res.json({
      totalUsers: Number(users.rows[0].count),
      totalScans: Number(scans.rows[0].count),
      activeThreatDomains: Number(threats.rows[0].count),
      pendingReports: Number(reports.rows[0].count),
    });
  } catch (err) { next(err); }
}

// ---------- GCash manual payments ----------

async function listManualPayments(req, res, next) {
  try {
    const { status = 'pending' } = req.query;
    const params = [];
    let where = '';
    if (status && status !== 'all') { params.push(status); where = `WHERE mp.status = $1`; }

    const { rows } = await db.query(
      `SELECT mp.id, mp.amount_php, mp.reference_number, mp.proof_image_path, mp.status,
              mp.admin_notes, mp.created_at, mp.reviewed_at,
              u.id AS user_id, u.email, u.full_name,
              p.code AS plan_code, p.name AS plan_name
       FROM manual_payments mp
       JOIN users u ON u.id = mp.user_id
       JOIN subscription_plans p ON p.id = mp.plan_id
       ${where}
       ORDER BY mp.created_at DESC LIMIT 200`,
      params
    );
    res.json({ items: rows });
  } catch (err) { next(err); }
}

async function getPaymentProof(req, res, next) {
  try {
    const { rows } = await db.query('SELECT proof_image_path FROM manual_payments WHERE id = $1', [req.params.id]);
    const record = rows[0];
    if (!record || !record.proof_image_path) return res.status(404).json({ error: 'No proof image for this payment' });

    // proof_image_path is a Supabase Storage object key (see paymentProofStorageService.js).
    // Redirect to a short-lived signed URL rather than serving the file directly -
    // the object lives in a private bucket, not on this server's filesystem.
    const signedUrl = await getPaymentProofSignedUrl(record.proof_image_path);
    res.redirect(signedUrl);
  } catch (err) { next(err); }
}

async function reviewManualPayment(req, res, next) {
  const client = await db.getClient();
  try {
    const { status, adminNotes } = req.body; // approved | rejected

    await client.query('BEGIN');

    const { rows } = await client.query(
      `UPDATE manual_payments SET status = $1, admin_notes = $2, reviewed_by = $3, reviewed_at = now(), updated_at = now()
       WHERE id = $4 AND status = 'pending' RETURNING *`,
      [status, adminNotes || null, req.user.id, req.params.id]
    );
    const payment = rows[0];
    if (!payment) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Pending payment not found (it may already have been reviewed)' });
    }

    if (status === 'approved') {
      // Superseding any existing active subscription for this user keeps
      // "one active plan per user" true even on upgrade/renewal.
      await client.query(
        `UPDATE subscriptions SET status = 'canceled', updated_at = now() WHERE user_id = $1 AND status = 'active'`,
        [payment.user_id]
      );
      await client.query(
        `INSERT INTO subscriptions (user_id, plan_id, status, provider, provider_ref, current_period_start, current_period_end)
         VALUES ($1, $2, 'active', 'gcash', $3, now(), now() + interval '30 days')`,
        [payment.user_id, payment.plan_id, payment.reference_number]
      );
    }

    await client.query(
      `INSERT INTO audit_logs (actor_id, action, target_type, target_id, metadata)
       VALUES ($1, $2, 'manual_payment', $3, $4)`,
      [req.user.id, `admin.payment.${status}`, payment.id, JSON.stringify({ adminNotes: adminNotes || null })]
    );

    await client.query('COMMIT');
    res.json(payment);
  } catch (err) {
    await client.query('ROLLBACK');
    next(err);
  } finally {
    client.release();
  }
}

module.exports = {
  bootstrapSelf,
  listUsers, updateUserStatus, subscriptionStats, scanStats,
  listThreatDomains, addThreatDomain, removeThreatDomain,
  listReports, reviewReport, analyticsOverview,
  listManualPayments, getPaymentProof, reviewManualPayment,
};
