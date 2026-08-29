const dns = require('dns').promises;
const net = require('net');

/**
 * Blocks server-side requests to private, loopback, link-local, and other
 * non-public address space. Used before any outbound fetch that is triggered
 * by user-supplied input (redirect resolution, future preview-image fetches,
 * etc.) to prevent SSRF against internal infrastructure and cloud metadata
 * endpoints (e.g. 169.254.169.254).
 *
 * This checks the *resolved* IP, not just the hostname string, so it also
 * catches DNS rebinding to a private address and IPv4-mapped/compressed
 * IPv6 tricks (::ffff:127.0.0.1, 0177.0.0.1, decimal/hex IP encodings, etc.)
 * to the extent Node's own resolver normalizes them.
 */

const BLOCKED_V4_RANGES = [
  ['0.0.0.0', '0.255.255.255'],       // "this" network
  ['10.0.0.0', '10.255.255.255'],     // RFC1918
  ['100.64.0.0', '100.127.255.255'],  // CGNAT
  ['127.0.0.0', '127.255.255.255'],   // loopback
  ['169.254.0.0', '169.254.255.255'], // link-local / cloud metadata
  ['172.16.0.0', '172.31.255.255'],   // RFC1918
  ['192.0.0.0', '192.0.0.255'],       // IETF protocol assignments
  ['192.168.0.0', '192.168.255.255'], // RFC1918
  ['198.18.0.0', '198.19.255.255'],   // benchmarking
  ['224.0.0.0', '255.255.255.255'],   // multicast / reserved
];

function ipToLong(ip) {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;
}

function isBlockedV4(ip) {
  const val = ipToLong(ip);
  return BLOCKED_V4_RANGES.some(([lo, hi]) => val >= ipToLong(lo) && val <= ipToLong(hi));
}

function isBlockedV6(ip) {
  const norm = ip.toLowerCase();
  if (norm === '::1') return true; // loopback
  if (norm === '::') return true; // unspecified
  if (norm.startsWith('fe80:') || norm.startsWith('fe8') || norm.startsWith('fe9') || norm.startsWith('fea') || norm.startsWith('feb')) return true; // link-local
  if (norm.startsWith('fc') || norm.startsWith('fd')) return true; // unique local (fc00::/7)
  // IPv4-mapped IPv6 (::ffff:a.b.c.d) - check the embedded v4 address too
  const mapped = norm.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped && isBlockedV4(mapped[1])) return true;
  return false;
}

function isBlockedIp(ip) {
  return net.isIP(ip) === 4 ? isBlockedV4(ip) : isBlockedV6(ip);
}

/**
 * Resolves `hostname` and throws if it is not safe to request server-side.
 * Call this immediately before every outbound axios request whose target
 * URL/hostname originated from user input.
 */
async function assertSafeToFetch(urlString) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    throw new Error('Invalid URL');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`Blocked scheme: ${parsed.protocol}`);
  }

  const hostname = parsed.hostname;

  // Literal IP in the URL - check directly, no DNS lookup needed.
  if (net.isIP(hostname)) {
    if (isBlockedIp(hostname)) throw new Error('Blocked target address');
    return;
  }

  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    throw new Error('Blocked target address');
  }

  // Resolve and check every returned address - if any resolve to private
  // space, refuse (defends against DNS rebinding between check and use too,
  // though the real defense against rebinding is re-checking right before
  // each hop, which resolveRedirectChain does).
  let addresses;
  try {
    addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new Error('Could not resolve host');
  }

  if (addresses.length === 0 || addresses.some((a) => isBlockedIp(a.address))) {
    throw new Error('Blocked target address');
  }
}

module.exports = { assertSafeToFetch, isBlockedIp };
