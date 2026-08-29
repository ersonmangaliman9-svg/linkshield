const { analyzeUrl } = require('./urlAnalysisService');
const { analyzeMessage } = require('./messageAnalysisService');

/**
 * Classifies a decoded QR payload (the Flutter app performs the actual camera decode
 * on-device with `mobile_scanner`; the backend only ever receives the decoded string -
 * QR images themselves are never uploaded, which keeps this fast and privacy-preserving).
 */
function classifyQrPayload(payload) {
  const trimmed = payload.trim();
  if (/^https?:\/\//i.test(trimmed) || /^www\./i.test(trimmed)) return 'url';
  if (/^(BEGIN:VCARD|MATMSG:|mailto:)/i.test(trimmed)) return 'contact_or_email';
  if (/^(WIFI:)/i.test(trimmed)) return 'wifi';
  if (/^\d{9,16}$/.test(trimmed.replace(/\s/g, ''))) return 'phone_or_number';
  return 'text';
}

/** Analyzes a decoded QR payload the same way a link or message would be analyzed. */
async function analyzeQrPayload(payload) {
  const kind = classifyQrPayload(payload);

  if (kind === 'url') {
    const urlResult = await analyzeUrl(payload);
    return { kind, urlResult };
  }

  if (kind === 'wifi') {
    // WIFI:T:WPA;S:SSID;P:password;; - flag if it's an open/unsecured network trick
    const indicators = [];
    if (/T:nopass/i.test(payload)) {
      indicators.push({ code: 'open_wifi_qr', label: 'QR connects to an open (unsecured) Wi-Fi network', severity: 'medium' });
    }
    return { kind, indicators };
  }

  // Fallback: treat as free text and run scam-pattern detection (covers fake payment
  // QR codes with embedded scam copy, malicious deep links disguised as plain text, etc.)
  const messageResult = analyzeMessage(payload);
  return { kind, messageResult };
}

module.exports = { classifyQrPayload, analyzeQrPayload };
