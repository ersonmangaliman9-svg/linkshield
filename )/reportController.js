const db = require('../config/db');

async function createReport(req, res, next) {
  try {
    const { reportedValue, reportType, category, description, scanId } = req.body;
    const { rows } = await db.query(
      `INSERT INTO scam_reports (reporter_id, scan_id, reported_value, report_type, category, description)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [req.user.id, scanId || null, reportedValue, reportType, category || null, description || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    next(err);
  }
}

async function listMyReports(req, res, next) {
  try {
    const { rows } = await db.query(
      'SELECT * FROM scam_reports WHERE reporter_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json({ items: rows });
  } catch (err) {
    next(err);
  }
}

module.exports = { createReport, listMyReports };
