const { extractDomain } = require('./urlAnalysisService');

// Pattern library - each entry: regex, human label, severity.
// Kept as data (not hardcoded across the codebase) so it can be extended/managed by admins.
const PATTERNS = [
  { code: 'otp_request', re: /\b(otp|one[- ]?time pin|verification code|security code)\b.{0,30}\b(send|share|reply|give)\b/i,
    label: 'Asks you to share an OTP or verification code', severity: 'critical' },
  { code: 'otp_mention', re: /\b(otp|one[- ]?time pin)\b/i,
    label: 'Message references an OTP / one-time PIN', severity: 'medium' },
  { code: 'payment_request', re: /\b(send|transfer|deposit)\b.{0,20}\b(gcash|paymaya|money|payment|fee|₱|php)\b/i,
    label: 'Requests a money transfer or upfront payment', severity: 'high' },
  { code: 'fake_reward', re: /\b(congratulations|you('| ha)ve (won|been selected)|claim your (prize|reward|gift))\b/i,
    label: 'Claims you won a prize or reward you did not enter for', severity: 'high' },
  { code: 'urgency_pressure', re: /\b(act now|expires? (today|soon|in \d+ (hours|minutes))|limited time|last chance|immediately)\b/i,
    label: 'Uses urgency or pressure tactics to rush a decision', severity: 'medium' },
  { code: 'account_threat', re: /\b(account (will be|has been) (suspended|locked|blocked|deactivated))\b/i,
    label: 'Threatens account suspension to provoke quick action', severity: 'high' },
  { code: 'impersonation', re: /\b(bank|bpi|bdo|gcash|paymaya|dhl|lbc|government|sss|philhealth|pag-?ibig)\b.{0,30}\b(verify|update|confirm)\b.{0,20}\b(account|details|information)\b/i,
    label: 'Impersonates a bank, courier, or government agency asking to "verify" details', severity: 'high' },
  { code: 'suspicious_greeting', re: /\bdear (customer|valued (customer|member)|user)\b/i,
    label: 'Generic greeting typical of mass-sent scam messages', severity: 'low' },
  { code: 'grammar_red_flag', re: /\b(kindly|do the needful|dear beneficiary)\b/i,
    label: 'Phrasing commonly seen in scam/fraud templates', severity: 'low' },
];

function extractUrls(text) {
  const urlRegex = /\bhttps?:\/\/[^\s]+|\bwww\.[^\s]+|\b[a-z0-9-]+\.(?:com|net|org|xyz|tk|ml|gq|top|info|click|link)(?:\/[^\s]*)?/gi;
  return [...new Set((text.match(urlRegex) || []).map((s) => s.trim()))];
}

/**
 * Analyzes free-text message content for scam patterns: fake rewards, impersonation,
 * OTP/payment requests, urgency tactics, and any embedded links.
 */
function analyzeMessage(text) {
  const matched = [];
  for (const p of PATTERNS) {
    if (p.re.test(text)) {
      matched.push({ code: p.code, label: p.label, severity: p.severity });
    }
  }

  const urls = extractUrls(text);
  if (urls.length > 0) {
    matched.push({
      code: 'contains_link',
      label: `Message contains ${urls.length} link${urls.length > 1 ? 's' : ''} that should be checked separately`,
      severity: 'medium',
    });
  }

  return { patterns: matched, extractedUrls: urls, domains: urls.map((u) => extractDomain(u)?.hostname).filter(Boolean) };
}

module.exports = { analyzeMessage, extractUrls };
