const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const authController = require('../controllers/authController');

const isDev = process.env.NODE_ENV !== 'production';

// En dev : limites très souples pour les tests
// En prod : limites strictes anti-abus
const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: isDev ? 100 : 5,
  message: { error: 'Too many OTP requests. Please wait 10 minutes.' },
  skip: () => isDev, // en dev : pas de limite du tout
});

const verifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: isDev ? 200 : 10,
  message: { error: 'Too many verification attempts. Please wait 10 minutes.' },
  skip: () => isDev, // en dev : pas de limite du tout
});

router.post('/request-otp', otpLimiter, authController.requestOtp);
router.post('/verify-otp', verifyLimiter, authController.verifyOtp);
router.post('/refresh', authController.refresh);

module.exports = router;
