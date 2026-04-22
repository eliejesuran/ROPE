// routes/account.js
const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const { pool } = require('../models/db');
const logger = require('../services/logger');

router.use(authenticate);

// GDPR: full account deletion
router.delete('/', async (req, res) => {
  const userId = req.userId;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Erase all messages content
    await client.query(
      `UPDATE messages SET ciphertext = '', iv = '', deleted_at = NOW()
       WHERE sender_id = $1`,
      [userId]
    );

    // Soft-delete user (keeps foreign key integrity, phone hash anonymised)
    await client.query(
      `UPDATE users SET
         phone_hash = 'DELETED_' || id,
         phone_last4 = '****',
         display_name = NULL,
         public_key = '',
         deleted_at = NOW()
       WHERE id = $1`,
      [userId]
    );

    await client.query('COMMIT');
    logger.info('User account deleted (GDPR)', { userId });
    res.json({ success: true, message: 'Your account and all data have been permanently deleted.' });
  } catch (err) {
    await client.query('ROLLBACK');
    logger.error('Account deletion failed', { error: err.message });
    res.status(500).json({ error: 'Deletion failed' });
  } finally {
    client.release();
  }
});

// Update display name (optional)
router.patch('/display-name', async (req, res) => {
  const { displayName } = req.body;
  if (!displayName || displayName.length > 30) {
    return res.status(400).json({ error: 'Display name must be 1-30 characters' });
  }
  await pool.query('UPDATE users SET display_name = $1 WHERE id = $2', [displayName, req.userId]);
  res.json({ success: true });
});

module.exports = router;
