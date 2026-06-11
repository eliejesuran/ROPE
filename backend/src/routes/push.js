const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const { pool } = require('../models/db');
const logger = require('../services/logger');

router.use(authenticate);

router.post('/register', async (req, res) => {
  const { token, platform } = req.body;
  if (!token || !platform) return res.status(400).json({ error: 'token and platform required' });
  if (!['ios', 'android'].includes(platform)) return res.status(400).json({ error: 'platform must be ios or android' });

  try {
    await pool.query(
      `INSERT INTO device_tokens (user_id, platform, token)
       VALUES ($1, $2, $3)
       ON CONFLICT (token) DO UPDATE SET user_id = $1, platform = $2, updated_at = NOW()`,
      [req.userId, platform, token]
    );
    res.json({ success: true });
  } catch (err) {
    logger.error('push/register error', { error: err.message });
    res.status(500).json({ error: 'Failed to register token' });
  }
});

router.delete('/unregister', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'token required' });

  try {
    await pool.query(
      'DELETE FROM device_tokens WHERE user_id = $1 AND token = $2',
      [req.userId, token]
    );
    res.json({ success: true });
  } catch (err) {
    logger.error('push/unregister error', { error: err.message });
    res.status(500).json({ error: 'Failed to unregister token' });
  }
});

module.exports = router;
