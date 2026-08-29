const axios = require('axios');
const logger = require('../utils/logger');

/**
 * Generates a plain-language explanation of WHY a scan received its risk score.
 * IMPORTANT: this service never determines the risk score or level itself - that
 * decision is made entirely by the deterministic rules engine in riskScoreService.js
 * using indicators + threat-intel provider signals. The AI's only job is to translate
 * that already-computed verdict into a clear explanation for the user.
 */
async function explainResult({ scanType, input, riskLevel, riskScore, indicators }) {
  const apiKey = process.env.ANTHROPIC_API_KEY;

  // Deterministic template fallback - always available even without an API key,
  // so the app never blocks on AI availability for its core safety function.
  const templated = templateExplanation({ scanType, riskLevel, riskScore, indicators });
  if (!apiKey) return { text: templated, source: 'template' };

  try {
    const indicatorList = indicators.map((i) => `- ${i.label} (severity: ${i.severity})`).join('\n');
    const prompt = `You are explaining a security scan result inside the LinkShield app.
Scan type: ${scanType}
Risk level: ${riskLevel} (score ${riskScore}/100)
Detected indicators:
${indicatorList || '- none'}

Write a short (2-4 sentence), plain-language explanation for a non-technical user of why this
result received this risk level. Do not invent indicators beyond the list above. Do not tell
the user the item is definitely safe even at low risk - encourage general caution. Never
instruct the user to open, click, or visit the link/content being scanned.`;

    const resp = await axios.post(
      'https://api.anthropic.com/v1/messages',
      {
        model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-6',
        max_tokens: 300,
        messages: [{ role: 'user', content: prompt }],
      },
      {
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json',
        },
        timeout: 8000,
      }
    );
    const text = resp.data.content?.map((b) => b.text || '').join('\n').trim();
    return { text: text || templated, source: 'ai' };
  } catch (err) {
    logger.error('AI explanation generation failed, using template fallback', { message: err.message });
    return { text: templated, source: 'template_fallback' };
  }
}

function templateExplanation({ scanType, riskLevel, riskScore, indicators }) {
  const top = indicators.slice(0, 3).map((i) => i.label.toLowerCase());
  const reasonText = top.length ? `mainly because: ${top.join('; ')}.` : 'based on our automated checks.';

  if (riskLevel === 'dangerous') {
    return `This ${scanType} scored ${riskScore}/100 and is flagged as DANGEROUS ${reasonText} We strongly recommend you do not open it, click any links, or share personal or payment information.`;
  }
  if (riskLevel === 'suspicious') {
    return `This ${scanType} scored ${riskScore}/100 and looks SUSPICIOUS ${reasonText} Proceed with caution and avoid entering sensitive information unless you can independently verify the source.`;
  }
  return `This ${scanType} scored ${riskScore}/100 and no major threats were detected ${reasonText} As always, stay cautious with unfamiliar links and never share OTPs or passwords.`;
}

module.exports = { explainResult };
