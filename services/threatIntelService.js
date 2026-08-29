const axios = require('axios');
const logger = require('../utils/logger');

const USE_MOCK = process.env.USE_MOCK_THREAT_DATA === 'true';

/**
 * Google Safe Browsing v4 lookup.
 * Docs: https://developers.google.com/safe-browsing/v4/lookup-api
 */
async function checkGoogleSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) return { available: false };

  try {
    const resp = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        client: { clientId: 'linkshield', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      },
      { timeout: 6000 }
    );
    const matches = resp.data.matches || [];
    return { available: true, flagged: matches.length > 0, matches };
  } catch (err) {
    logger.error('Safe Browsing lookup failed', { message: err.message });
    return { available: false, error: true };
  }
}

/** VirusTotal URL report lookup (v3). Requires the URL to already be submitted/known. */
async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { available: false };

  try {
    const urlId = Buffer.from(url).toString('base64').replace(/=+$/, '');
    const resp = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': apiKey },
      timeout: 6000,
    });
    const stats = resp.data?.data?.attributes?.last_analysis_stats || {};
    const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
    return { available: true, flagged: malicious > 0, stats };
  } catch (err) {
    // 404 just means VT hasn't scanned this URL before - not an error condition
    if (err.response && err.response.status === 404) {
      return { available: true, flagged: false, stats: null };
    }
    logger.error('VirusTotal lookup failed', { message: err.message });
    return { available: false, error: true };
  }
}

/** abuse.ch URLhaus lookup - free, no key required. */
async function checkUrlhaus(url) {
  const endpoint = process.env.URLHAUS_API_URL || 'https://urlhaus-api.abuse.ch/v1';
  try {
    const resp = await axios.post(
      `${endpoint}/url/`,
      new URLSearchParams({ url }),
      { timeout: 6000 }
    );
    const data = resp.data;
    return { available: true, flagged: data.query_status === 'ok', data };
  } catch (err) {
    logger.error('URLhaus lookup failed', { message: err.message });
    return { available: false, error: true };
  }
}

/** Deterministic mock signals for demo/dev environments without API keys configured. */
function mockSignals(hostname) {
  const knownBadDemo = ['scam-example.tk', 'free-gcash-reward.xyz', 'paypal-verify-login.com'];
  const flagged = knownBadDemo.includes(hostname);
  return {
    google_safe_browsing: { available: true, flagged, mocked: true },
    virustotal: { available: true, flagged, stats: flagged ? { malicious: 6, suspicious: 2 } : { malicious: 0, suspicious: 0 }, mocked: true },
    urlhaus: { available: true, flagged, mocked: true },
  };
}

/**
 * Aggregates signals from all configured threat-intel providers.
 * Falls back to deterministic mock data (clearly labeled) when no API keys are set,
 * so the app remains fully demoable without live keys. Real deployments must set
 * the provider API keys in .env - the AI layer never makes the final call alone.
 */
async function getThreatIntelSignals(finalUrl, hostname) {
  if (USE_MOCK || (!process.env.GOOGLE_SAFE_BROWSING_API_KEY && !process.env.VIRUSTOTAL_API_KEY)) {
    return mockSignals(hostname);
  }

  const [gsb, vt, uh] = await Promise.all([
    checkGoogleSafeBrowsing(finalUrl),
    checkVirusTotal(finalUrl),
    checkUrlhaus(finalUrl),
  ]);

  return { google_safe_browsing: gsb, virustotal: vt, urlhaus: uh };
}

module.exports = { getThreatIntelSignals, checkGoogleSafeBrowsing, checkVirusTotal, checkUrlhaus };
