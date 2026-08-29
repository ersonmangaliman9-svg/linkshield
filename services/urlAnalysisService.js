const axios = require('axios');
const { URL } = require('url');
const db = require('../config/db');
const { assertSafeToFetch } = require('./ssrfGuard');

// Well-known URL shorteners - not malicious by themselves, but hide the real destination
const SHORTENER_DOMAINS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'cutt.ly', 'rebrand.ly', 'shorte.st', 'adf.ly',
]);

// Common brand keywords abused in look-alike / typosquat domains
const BRAND_KEYWORDS = [
  'paypal', 'gcash', 'bpi', 'bdo', 'metrobank', 'facebook', 'google',
  'microsoft', 'apple', 'amazon', 'netflix', 'instagram', 'whatsapp',
  'lazada', 'shopee', 'dhl', 'lbc',
];

const SUSPICIOUS_TLDS = new Set(['zip', 'xyz', 'top', 'gq', 'tk', 'ml', 'work', 'click', 'link']);

function extractDomain(rawUrl) {
  try {
    const normalized = /^https?:\/\//i.test(rawUrl) ? rawUrl : `http://${rawUrl}`;
    const u = new URL(normalized);
    return { hostname: u.hostname.toLowerCase(), protocol: u.protocol, normalized };
  } catch (e) {
    return null;
  }
}

/** Levenshtein-lite similarity check for typosquatting against known brand keywords. */
function findBrandLookalike(hostname) {
  const parts = hostname.replace(/^www\./, '').split('.');
  const core = parts[0] || '';
  for (const brand of BRAND_KEYWORDS) {
    if (core === brand) continue; // exact match to brand's own domain path is fine
    if (core.includes(brand) && hostname !== `${brand}.com`) {
      return brand;
    }
    // simple hyphen/insertion pattern: "paypal-secure", "secure-paypal"
    if (core.includes(`${brand}-`) || core.includes(`-${brand}`)) {
      return brand;
    }
  }
  return null;
}

/**
 * Follow redirects manually (max 5 hops) to reveal the true final destination.
 *
 * SSRF guard: every hop is validated with assertSafeToFetch() immediately
 * before it is requested - not just the first URL - because a scanned link
 * can legitimately redirect through public infrastructure and then land on
 * an internal address (e.g. an attacker-controlled public URL that 302s to
 * http://169.254.169.254/...). Checking only the initial input would miss
 * that entirely.
 */
async function resolveRedirectChain(startUrl) {
  const chain = [startUrl];
  let current = startUrl;
  let blockedInternalRedirect = false;
  for (let i = 0; i < 5; i += 1) {
    try {
      await assertSafeToFetch(current);
    } catch (err) {
      // Target resolves to private/internal address space, or an unsupported
      // scheme - stop here rather than following it. If this happened on a
      // hop after the first (i.e. a *redirect* led here, not the original
      // input), that's a meaningful signal on its own - flag it below.
      if (i > 0) blockedInternalRedirect = true;
      break;
    }
    try {
      const resp = await axios.get(current, {
        maxRedirects: 0,
        timeout: 5000,
        validateStatus: (s) => s < 400,
      });
      if (resp.status >= 300 && resp.status < 400 && resp.headers.location) {
        current = new URL(resp.headers.location, current).toString();
        chain.push(current);
      } else {
        break;
      }
    } catch (err) {
      // If the request itself redirects via axios internal handling or fails, stop here
      break;
    }
  }
  return { chain, blockedInternalRedirect };
}

/**
 * Runs local heuristic analysis on a URL: domain parsing, HTTPS, shortener detection,
 * brand look-alike / typosquat detection, suspicious TLD, and a lookup against the
 * local threat_domains table (populated from Safe Browsing / VirusTotal / URLhaus / reports).
 */
async function analyzeUrl(rawUrl) {
  const parsed = extractDomain(rawUrl);
  const indicators = [];

  if (!parsed) {
    indicators.push({ code: 'malformed_url', label: 'URL could not be parsed', severity: 'high' });
    return { valid: false, indicators, hostname: null, finalUrl: rawUrl, usesHttps: false, redirectChain: [] };
  }

  const { hostname, protocol } = parsed;
  const usesHttps = protocol === 'https:';
  if (!usesHttps) {
    indicators.push({ code: 'no_https', label: 'Site does not use secure HTTPS connection', severity: 'medium' });
  }

  const isShortener = SHORTENER_DOMAINS.has(hostname);
  if (isShortener) {
    indicators.push({ code: 'shortener', label: 'Link uses a URL shortener, hiding the real destination', severity: 'low' });
  }

  const lookalikeBrand = findBrandLookalike(hostname);
  if (lookalikeBrand) {
    indicators.push({
      code: 'brand_lookalike',
      label: `Domain resembles "${lookalikeBrand}" but is not the official domain`,
      severity: 'high',
    });
  }

  const tld = hostname.split('.').pop();
  if (SUSPICIOUS_TLDS.has(tld)) {
    indicators.push({ code: 'suspicious_tld', label: `Uses a top-level domain (.${tld}) often abused for scams`, severity: 'medium' });
  }

  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname)) {
    indicators.push({ code: 'raw_ip', label: 'Link points directly to an IP address instead of a domain name', severity: 'high' });
  }

  if ((hostname.match(/-/g) || []).length >= 3) {
    indicators.push({ code: 'excessive_hyphens', label: 'Domain contains an unusually high number of hyphens', severity: 'low' });
  }

  // Direct input pointing at private/internal address space (not via a redirect)
  // is itself a strong signal - e.g. someone probing the scanner rather than a
  // real phishing link - and we should not even attempt to fetch it.
  try {
    await assertSafeToFetch(parsed.normalized);
  } catch (e) {
    indicators.push({ code: 'internal_target_blocked', label: 'Link points to an internal or non-public address and was not fetched', severity: 'critical' });
  }

  // Redirect resolution (best-effort; skipped gracefully if network fails/sandboxed)
  let redirectChain = [parsed.normalized];
  let finalUrl = parsed.normalized;
  try {
    const resolved = await resolveRedirectChain(parsed.normalized);
    redirectChain = resolved.chain;
    finalUrl = redirectChain[redirectChain.length - 1];
    if (resolved.blockedInternalRedirect) {
      indicators.push({ code: 'internal_redirect_blocked', label: 'Link redirects to an internal or non-public address', severity: 'critical' });
    }
    if (redirectChain.length > 2) {
      indicators.push({ code: 'multiple_redirects', label: `Link redirects through ${redirectChain.length - 1} hops before reaching its destination`, severity: 'medium' });
    }
  } catch (e) {
    // network unavailable in this environment - continue with local heuristics only
  }

  // Local threat_domains table lookup
  const { rows } = await db.query(
    'SELECT category, severity, source FROM threat_domains WHERE domain = $1 AND is_active = TRUE',
    [hostname]
  );
  if (rows.length > 0) {
    const match = rows[0];
    indicators.push({
      code: 'known_threat',
      label: `Domain is listed as ${match.category} in the threat database (source: ${match.source})`,
      severity: 'critical',
    });
  }

  return { valid: true, hostname, finalUrl, usesHttps, redirectChain, isShortener, indicators };
}

module.exports = { analyzeUrl, extractDomain, findBrandLookalike };
