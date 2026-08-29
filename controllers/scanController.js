const db = require('../config/db');
const { analyzeUrl } = require('../services/urlAnalysisService');
const { getThreatIntelSignals } = require('../services/threatIntelService');
const { computeUrlRiskScore, computeMessageRiskScore } = require('../services/riskScoreService');
const { analyzeMessage } = require('../services/messageAnalysisService');
const { analyzeQrPayload } = require('../services/qrService');
const { explainResult } = require('../services/aiExplanationService');

/**
 * Atomically reserves one scan slot against the caller's monthly quota.
 *
 * The previous implementation (SELECT current usage, compare in JS, then a
 * separate UPDATE to increment after the scan finished) had a check-then-act
 * race: two concurrent requests near the limit could both pass the check
 * before either had incremented, letting a user exceed their quota. This
 * version does the reset-if-expired and the increment-if-under-limit as a
 * single atomic UPDATE each, so the database - not application code - is
 * what enforces "only increment if still under the limit".
 *
 * Because the actual scan work (URL analysis, threat-intel calls, the AI
 * explanation) can take a few seconds and shouldn't happen inside an open
 * transaction, the slot is reserved up front and released with
 * releaseScanSlot() if the scan fails before it's persisted.
 */
async function reserveScanSlot(userId) {
  // Roll the period over first if it has expired. Harmless if two requests
  // race here - both resets are idempotent no-ops once period_reset_at is
  // in the future.
  await db.query(
    `UPDATE users SET scans_used_this_period = 0, period_reset_at = now() + interval '30 days'
     WHERE id = $1 AND period_reset_at < now()`,
    [userId]
  );

  const { rows } = await db.query(
    `UPDATE users u
     SET scans_used_this_period = u.scans_used_this_period + 1
     FROM (
       SELECT p.scan_limit, p.code AS plan_code
       FROM subscriptions s
       JOIN subscription_plans p ON p.id = s.plan_id
       WHERE s.user_id = $1 AND s.status = 'active'
       LIMIT 1
     ) plan
     WHERE u.id = $1 AND (plan.scan_limit IS NULL OR u.scans_used_this_period < plan.scan_limit)
     RETURNING u.scans_used_this_period AS used, plan.scan_limit, plan.plan_code`,
    [userId]
  );

  if (!rows[0]) return { allowed: false };
  return { allowed: true, unlimited: rows[0].scan_limit === null, planCode: rows[0].plan_code };
}

/** Gives back a reserved slot if the scan failed after reserveScanSlot() succeeded. */
async function releaseScanSlot(userId) {
  await db.query(
    'UPDATE users SET scans_used_this_period = GREATEST(0, scans_used_this_period - 1) WHERE id = $1',
    [userId]
  );
}

async function persistScan({ userId, scanType, inputRaw, origin, riskScore, riskLevel, domain, finalUrl, redirectChain, usesHttps, indicators, providerSignals, aiExplanation }) {
  const scanInsert = await db.query(
    `INSERT INTO scans (user_id, scan_type, input_raw, source, origin_app)
     VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`,
    [userId, scanType, inputRaw, origin?.source || 'app', origin?.originApp || null]
  );
  const scan = scanInsert.rows[0];

  const resultInsert = await db.query(
    `INSERT INTO scan_results
      (scan_id, risk_score, risk_level, domain, final_url, redirect_chain, uses_https, indicators, provider_signals, ai_explanation)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     RETURNING *`,
    [scan.id, riskScore, riskLevel, domain || null, finalUrl || null, JSON.stringify(redirectChain || []),
      usesHttps ?? null, JSON.stringify(indicators || []), JSON.stringify(providerSignals || {}), aiExplanation || null]
  );

  return { scan, result: resultInsert.rows[0] };
}

async function scanLink(req, res, next) {
  const userId = req.user.id;
  let reserved = false;
  try {
    const { url, source, originApp } = req.body;
    const quota = await reserveScanSlot(userId);
    if (!quota.allowed) {
      return res.status(402).json({ error: 'Monthly scan limit reached. Upgrade to Plus for unlimited scans.' });
    }
    reserved = true;

    const analysis = await analyzeUrl(url);
    if (!analysis.valid) {
      await releaseScanSlot(userId);
      return res.status(422).json({ error: 'Could not parse the provided URL' });
    }

    const providerSignals = await getThreatIntelSignals(analysis.finalUrl, analysis.hostname);
    const { score, level, indicators } = computeUrlRiskScore({ indicators: analysis.indicators, providerSignals });

    const aiExpl = await explainResult({ scanType: 'link', input: url, riskLevel: level, riskScore: score, indicators });

    const { scan, result } = await persistScan({
      userId, scanType: 'link', inputRaw: url, origin: { source, originApp },
      riskScore: score, riskLevel: level, domain: analysis.hostname, finalUrl: analysis.finalUrl,
      redirectChain: analysis.redirectChain, usesHttps: analysis.usesHttps, indicators, providerSignals,
      aiExplanation: aiExpl.text,
    });

    res.status(201).json({ scanId: scan.id, ...result });
  } catch (err) {
    if (reserved) await releaseScanSlot(userId).catch(() => {});
    next(err);
  }
}

async function scanQr(req, res, next) {
  const userId = req.user.id;
  let reserved = false;
  try {
    const { payload, source } = req.body;
    const quota = await reserveScanSlot(userId);
    if (!quota.allowed) {
      return res.status(402).json({ error: 'Monthly scan limit reached. Upgrade to Plus for unlimited scans.' });
    }
    reserved = true;

    const qrResult = await analyzeQrPayload(payload);
    let score = 0; let level = 'safe'; let indicators = []; let domain = null; let finalUrl = null; let usesHttps = null; let providerSignals = {};

    if (qrResult.kind === 'url' && qrResult.urlResult.valid) {
      providerSignals = await getThreatIntelSignals(qrResult.urlResult.finalUrl, qrResult.urlResult.hostname);
      const scored = computeUrlRiskScore({ indicators: qrResult.urlResult.indicators, providerSignals });
      score = scored.score; level = scored.level; indicators = scored.indicators;
      domain = qrResult.urlResult.hostname; finalUrl = qrResult.urlResult.finalUrl; usesHttps = qrResult.urlResult.usesHttps;
    } else if (qrResult.kind === 'wifi') {
      const scored = computeMessageRiskScore({ patterns: qrResult.indicators || [] });
      score = scored.score; level = scored.level; indicators = scored.indicators;
    } else {
      const scored = computeMessageRiskScore({ patterns: qrResult.messageResult?.patterns || [] });
      score = scored.score; level = scored.level; indicators = scored.indicators;
    }

    const aiExpl = await explainResult({ scanType: 'QR code', input: payload, riskLevel: level, riskScore: score, indicators });

    const { scan, result } = await persistScan({
      userId, scanType: 'qr', inputRaw: payload, origin: { source },
      riskScore: score, riskLevel: level, domain, finalUrl, redirectChain: [], usesHttps, indicators, providerSignals,
      aiExplanation: aiExpl.text,
    });

    res.status(201).json({ scanId: scan.id, qrKind: qrResult.kind, ...result });
  } catch (err) {
    if (reserved) await releaseScanSlot(userId).catch(() => {});
    next(err);
  }
}

async function scanMessage(req, res, next) {
  const userId = req.user.id;
  let reserved = false;
  try {
    const { text, source, originApp } = req.body;
    const quota = await reserveScanSlot(userId);
    if (!quota.allowed) {
      return res.status(402).json({ error: 'Monthly scan limit reached. Upgrade to Plus for unlimited scans.' });
    }
    reserved = true;

    const msgAnalysis = analyzeMessage(text);
    const { score, level, indicators } = computeMessageRiskScore({ patterns: msgAnalysis.patterns });

    // If the message contains links, factor in a quick check of the first one too
    let providerSignals = {};
    let domain = null;
    if (msgAnalysis.extractedUrls.length > 0) {
      const urlAnalysis = await analyzeUrl(msgAnalysis.extractedUrls[0]);
      if (urlAnalysis.valid) {
        domain = urlAnalysis.hostname;
        providerSignals = await getThreatIntelSignals(urlAnalysis.finalUrl, urlAnalysis.hostname);
        const urlScored = computeUrlRiskScore({ indicators: urlAnalysis.indicators, providerSignals });
        indicators.push(...urlScored.indicators);
      }
    }

    const finalScore = Math.min(100, score + (providerSignals.google_safe_browsing?.flagged ? 20 : 0));
    const finalLevel = finalScore >= 60 ? 'dangerous' : finalScore >= 25 ? 'suspicious' : 'safe';

    const aiExpl = await explainResult({ scanType: 'message', input: text, riskLevel: finalLevel, riskScore: finalScore, indicators });

    const { scan, result } = await persistScan({
      userId, scanType: 'message', inputRaw: text, origin: { source, originApp },
      riskScore: finalScore, riskLevel: finalLevel, domain, finalUrl: null, redirectChain: [], usesHttps: null,
      indicators, providerSignals, aiExplanation: aiExpl.text,
    });

    res.status(201).json({ scanId: scan.id, extractedUrls: msgAnalysis.extractedUrls, ...result });
  } catch (err) {
    if (reserved) await releaseScanSlot(userId).catch(() => {});
    next(err);
  }
}

async function getHistory(req, res, next) {
  try {
    const { type, level, q, page = 1, pageSize = 20 } = req.query;
    const conditions = ['s.user_id = $1'];
    const params = [req.user.id];
    let idx = 2;

    if (type) { conditions.push(`s.scan_type = $${idx}`); params.push(type); idx += 1; }
    if (level) { conditions.push(`r.risk_level = $${idx}`); params.push(level); idx += 1; }
    if (q) { conditions.push(`s.input_raw ILIKE $${idx}`); params.push(`%${q}%`); idx += 1; }

    const offset = (Number(page) - 1) * Number(pageSize);
    params.push(Number(pageSize), offset);

    const { rows } = await db.query(
      `SELECT s.id, s.scan_type, s.input_raw, s.origin_app, s.created_at,
              r.risk_score, r.risk_level, r.domain, r.ai_explanation
       FROM scans s
       JOIN scan_results r ON r.scan_id = s.id
       WHERE ${conditions.join(' AND ')}
       ORDER BY s.created_at DESC
       LIMIT $${idx} OFFSET $${idx + 1}`,
      params
    );
    res.json({ items: rows, page: Number(page), pageSize: Number(pageSize) });
  } catch (err) {
    next(err);
  }
}

async function getScanDetail(req, res, next) {
  try {
    const { rows } = await db.query(
      `SELECT s.*, r.risk_score, r.risk_level, r.domain, r.final_url, r.redirect_chain,
              r.uses_https, r.indicators, r.provider_signals, r.ai_explanation
       FROM scans s JOIN scan_results r ON r.scan_id = s.id
       WHERE s.id = $1 AND s.user_id = $2`,
      [req.params.id, req.user.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Scan not found' });
    res.json(rows[0]);
  } catch (err) {
    next(err);
  }
}

async function deleteScan(req, res, next) {
  try {
    const result = await db.query('DELETE FROM scans WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Scan not found' });
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
}

module.exports = { scanLink, scanQr, scanMessage, getHistory, getScanDetail, deleteScan };
