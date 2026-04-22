const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const authController = require('../controllers/authController');

// Strict rate limit on OTP endpoints to prevent abuse
const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 min
  max: 5,
  message: { error: 'Too many OTP requests. Please wait 10 minutes.' },
});

const verifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: { error: 'Too many verification attempts. Please wait 10 minutes.' },
});

/**
 * POST /api/auth/request-otp
 * Body: { phone: "+32471234567" }
 * Sends OTP to phone number (hardcoded in Sprint 1)
 */
router.post('/request-otp', otpLimiter, authController.requestOtp);

/**
 * POST /api/auth/verify-otp
 * Body: { phone: "+32471234567", code: "123456", publicKey: "<base64>" }
 * Returns: { token: "<jwt>", user: { id, displayName } }
 */
router.post('/verify-otp', verifyLimiter, authController.verifyOtp);

/**
 * POST /api/auth/refresh
 * Header: Authorization: Bearer <token>
 */
router.post('/refresh', authController.refresh);

module.exports = router;
