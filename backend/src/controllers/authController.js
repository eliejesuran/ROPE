const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { pool } = require('../models/db');
const { getRedis } = require('../services/redis');
const smsService = require('../services/sms');
const logger = require('../services/logger');

// Normalise phone to E.164 format (basic validation)
function normalisePhone(phone) {
  const cleaned = phone.replace(/\s+/g, '').replace(/-/g, '');
  if (!/^\+[1-9]\d{6,14}$/.test(cleaned)) {
    throw new Error('Invalid phone number format. Use E.164 (e.g. +32471234567)');
  }
  return cleaned;
}

// Deterministic hash for phone lookup (SHA-256 + pepper)
// Used for finding existing users — bcrypt is random so can't be used for lookup
function deterministicPhoneHash(phone, pepper) {
  return crypto.createHmac('sha256', pepper).update(phone).digest('hex');
}

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function signToken(userId) {
  return jwt.sign(
    { sub: userId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '30d' }
  );
}

// ── Request OTP ──────────────────────────────────────────────────────────────
exports.requestOtp = async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone number required' });

    const normalisedPhone = normalisePhone(phone);
    // Use deterministic hash so the same phone always maps to the same record
    const phoneHash = deterministicPhoneHash(normalisedPhone, process.env.SERVER_PEPPER);

    // Generate OTP (bypass in dev mode)
    const otp = process.env.OTP_BYPASS_ENABLED === 'true'
      ? process.env.OTP_BYPASS_CODE
      : generateOtp();

    const codeHash = await bcrypt.hash(otp, 10);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    await pool.query(
      `INSERT INTO otp_codes (phone_hash, code_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [phoneHash, codeHash, expiresAt]
    );

    // Send SMS (noop in dev bypass mode)
    await smsService.sendOtp(normalisedPhone, otp);

    logger.info('OTP requested', { phoneLast4: normalisedPhone.slice(-4) });

    res.json({
      success: true,
      expiresIn: 300,
      // In dev mode, return the code directly so you don't need SMS
      ...(process.env.OTP_BYPASS_ENABLED === 'true' && { devCode: otp }),
    });
  } catch (err) {
    logger.error('requestOtp error', { error: err.message });
    res.status(400).json({ error: err.message });
  }
};

// ── Verify OTP ───────────────────────────────────────────────────────────────
exports.verifyOtp = async (req, res) => {
  try {
    const { phone, code, publicKey } = req.body;

    if (!phone || !code || !publicKey) {
      return res.status(400).json({ error: 'phone, code and publicKey are required' });
    }

    const normalisedPhone = normalisePhone(phone);

    // Find valid, unused OTP for this phone
    // We must check all recent OTPs (bcrypt hash comparison)
    const { rows: otpRows } = await pool.query(
      `SELECT id, phone_hash, code_hash, attempts
       FROM otp_codes
       WHERE expires_at > NOW() AND used = FALSE
       ORDER BY created_at DESC
       LIMIT 10`
    );

    let validOtp = null;
    for (const row of otpRows) {
      const expectedHash = deterministicPhoneHash(normalisedPhone, process.env.SERVER_PEPPER);
      const phoneMatch = (expectedHash === row.phone_hash);
      if (phoneMatch) {
        if (row.attempts >= 5) {
          return res.status(429).json({ error: 'Too many attempts. Request a new code.' });
        }
        const codeMatch = await bcrypt.compare(code, row.code_hash);
        if (codeMatch) {
          validOtp = row;
          break;
        } else {
          // Increment attempts
          await pool.query(
            'UPDATE otp_codes SET attempts = attempts + 1 WHERE id = $1',
            [row.id]
          );
        }
      }
    }

    if (!validOtp) {
      return res.status(401).json({ error: 'Invalid or expired code' });
    }

    // Mark OTP as used
    await pool.query('UPDATE otp_codes SET used = TRUE WHERE id = $1', [validOtp.id]);

    const phoneLast4 = normalisedPhone.slice(-4);
    // Use deterministic hash so the same phone always maps to the same record
    const phoneHash = deterministicPhoneHash(normalisedPhone, process.env.SERVER_PEPPER);

    // Upsert user
    const { rows: userRows } = await pool.query(
      `INSERT INTO users (phone_hash, phone_last4, public_key)
       VALUES ($1, $2, $3)
       ON CONFLICT (phone_hash) DO UPDATE
         SET public_key = EXCLUDED.public_key,
             last_seen_at = NOW()
       RETURNING id, display_name`,
      [phoneHash, phoneLast4, publicKey]
    );

    const user = userRows[0];
    const token = signToken(user.id);

    logger.info('User authenticated', { userId: user.id });

    res.json({
      token,
      user: {
        id: user.id,
        displayName: user.display_name,
        phoneLast4,
      },
    });
  } catch (err) {
    logger.error('verifyOtp error', { error: err.message });
    res.status(500).json({ error: 'Authentication failed' });
  }
};

// ── Refresh token ─────────────────────────────────────────────────────────────
exports.refresh = async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const newToken = signToken(decoded.sub);

    res.json({ token: newToken });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};
