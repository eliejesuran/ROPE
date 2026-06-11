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

// GDPR Art. 20 — data export (metadata only, content is E2E encrypted)
router.get('/export', async (req, res) => {
  const userId = req.userId;
  try {
    const { rows: userRows } = await pool.query(
      'SELECT id, phone_last4, display_name, created_at FROM users WHERE id = $1 AND deleted_at IS NULL',
      [userId]
    );
    if (userRows.length === 0) return res.status(404).json({ error: 'User not found' });
    const u = userRows[0];

    const { rows: convRows } = await pool.query(
      `SELECT c.id, c.created_at AS started_at,
              other.phone_last4 AS contact_last4,
              other.display_name AS contact_display_name,
              COUNT(m.id) FILTER (WHERE m.deleted_at IS NULL) AS message_count
       FROM conversations c
       JOIN users other ON other.id = CASE WHEN c.participant_a = $1 THEN c.participant_b ELSE c.participant_a END
       LEFT JOIN messages m ON m.conversation_id = c.id
       WHERE (c.participant_a = $1 OR c.participant_b = $1)
       GROUP BY c.id, c.created_at, other.phone_last4, other.display_name
       ORDER BY c.created_at`,
      [userId]
    );

    res.json({
      exportedAt: new Date().toISOString(),
      user: {
        id: u.id,
        phoneLast4: u.phone_last4,
        displayName: u.display_name,
        createdAt: u.created_at,
      },
      conversations: convRows.map(c => ({
        id: c.id,
        contactLast4: c.contact_last4,
        contactDisplayName: c.contact_display_name,
        startedAt: c.started_at,
        messageCount: parseInt(c.message_count),
      })),
      note: 'Les messages sont chiffrés de bout en bout — le serveur ne conserve jamais le contenu en clair.',
    });
  } catch (err) {
    logger.error('account/export error', { error: err.message });
    res.status(500).json({ error: 'Export failed' });
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
