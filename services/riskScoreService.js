const SEVERITY_WEIGHTS = {
  low: 5,
  medium: 15,
  high: 30,
  critical: 50,
};

/**
 * Combines local heuristic indicators with external provider signals into a single
 * 0-100 risk score. This is a deterministic, auditable rules engine - NOT an AI model -
 * per the product requirement that AI only explains results, never decides them alone.
 */
function computeUrlRiskScore({ indicators = [], providerSignals = {} }) {
  let score = 0;
  const contributingIndicators = [...indicators];

  for (const ind of indicators) {
    score += SEVERITY_WEIGHTS[ind.severity] || 0;
  }

  const { google_safe_browsing: gsb, virustotal: vt, urlhaus: uh } = providerSignals;

  if (gsb?.flagged) {
    score += 45;
    contributingIndicators.push({ code: 'gsb_flagged', label: 'Flagged by Google Safe Browsing', severity: 'critical' });
  }
  if (vt?.flagged) {
    score += 35;
    contributingIndicators.push({ code: 'vt_flagged', label: 'Flagged as malicious by VirusTotal engines', severity: 'critical' });
  }
  if (uh?.flagged) {
    score += 40;
    contributingIndicators.push({ code: 'urlhaus_flagged', label: 'Listed in URLhaus malware/phishing database', severity: 'critical' });
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  return { score, level: levelForScore(score), indicators: contributingIndicators };
}

function levelForScore(score) {
  if (score >= 60) return 'dangerous';
  if (score >= 25) return 'suspicious';
  return 'safe';
}

/** Scam-pattern based scoring for free-text messages (SMS/chat/email body). */
function computeMessageRiskScore({ patterns = [] }) {
  let score = 0;
  for (const p of patterns) {
    score += SEVERITY_WEIGHTS[p.severity] || 0;
  }
  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, level: levelForScore(score), indicators: patterns };
}

module.exports = { computeUrlRiskScore, computeMessageRiskScore, levelForScore };
