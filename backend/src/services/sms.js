const logger = require('./logger');

/**
 * SMS Service
 *
 * Sprint 1: OTP_BYPASS_ENABLED=true → code returned in API response, no SMS sent
 * Sprint 2: Switch to Infobip (EU-based, GDPR compliant, Zagreb, Croatia)
 *           https://www.infobip.com/
 *
 * Why Infobip over Twilio?
 * - Headquartered in EU (Croatia)
 * - GDPR compliant by design
 * - Data processed and stored in EU
 * - No US data transfers
 */

async function sendOtp(phoneNumber, otp) {
  if (process.env.OTP_BYPASS_ENABLED === 'true') {
    logger.warn('[DEV MODE] SMS not sent. OTP returned in API response.', {
      phoneLast4: phoneNumber.slice(-4),
    });
    return { success: true, dev: true };
  }

  // Sprint 2: Infobip implementation
  // const response = await fetch(`${process.env.INFOBIP_BASE_URL}/sms/2/text/advanced`, {
  //   method: 'POST',
  //   headers: {
  //     'Authorization': `App ${process.env.INFOBIP_API_KEY}`,
  //     'Content-Type': 'application/json',
  //   },
  //   body: JSON.stringify({
  //     messages: [{
  //       from: 'ROPE',
  //       destinations: [{ to: phoneNumber }],
  //       text: `Your ROPE code: ${otp}. Valid 5 minutes. Never share it.`,
  //     }],
  //   }),
  // });
  // if (!response.ok) throw new Error('SMS delivery failed');

  throw new Error('SMS provider not configured. Set OTP_BYPASS_ENABLED=true for development.');
}

module.exports = { sendOtp };
