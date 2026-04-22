// routes/contacts.js
const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const bcrypt = require('bcryptjs');
const { pool } = require('../models/db');
const logger = require('../services/logger');

router.use(authenticate);

/**
 * POST /api/contacts/find
 * Body: { phone: "+32471234567" }
 * Finds a user by phone number and creates/returns a conversation.
 * The phone number is hashed before lookup — server never sees it in clear.
 */
router.post('/find', async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone required' });

    const cleaned = phone.replace(/\s+/g, '').replace(/-/g, '');

    // We must compare against all stored phone hashes
    const { rows: users } = await pool.query(
      `SELECT id, phone_hash, phone_last4, display_name, public_key
       FROM users WHERE deleted_at IS NULL`
    );

    let found = null;
    for (const user of users) {
      if (user.id === req.userId) continue;
      const match = await bcrypt.compare(cleaned + process.env.SERVER_PEPPER, user.phone_hash);
      if (match) { found = user; break; }
    }

    if (!found) {
      return res.status(404).json({ error: 'User not found or not registered on ROPE' });
    }

    // Ensure conversation exists (canonical order to avoid duplicates)
    const [a, b] = [req.userId, found.id].sort();
    const { rows: convRows } = await pool.query(
      `INSERT INTO conversations (participant_a, participant_b)
       VALUES ($1, $2)
       ON CONFLICT (participant_a, participant_b) DO NOTHING
       RETURNING id`,
      [a, b]
    );

    const convId = convRows[0]?.id || (await pool.query(
      'SELECT id FROM conversations WHERE participant_a = $1 AND participant_b = $2',
      [a, b]
    )).rows[0].id;

    res.json({
      user: {
        id: found.id,
        displayName: found.display_name,
        phoneLast4: found.phone_last4,
        publicKey: found.public_key,
      },
      conversationId: convId,
    });
  } catch (err) {
    logger.error('contacts/find error', { error: err.message });
    res.status(500).json({ error: 'Search failed' });
  }
});

/**
 * GET /api/contacts/conversations
 * Returns all conversations for the current user
 */
router.get('/conversations', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT c.id as conversation_id,
              u.id as contact_id,
              u.display_name,
              u.phone_last4,
              u.public_key,
              (SELECT ciphertext FROM messages m
               WHERE m.conversation_id = c.id AND m.deleted_at IS NULL
               ORDER BY sent_at DESC LIMIT 1) as last_ciphertext,
              (SELECT sent_at FROM messages m
               WHERE m.conversation_id = c.id
               ORDER BY sent_at DESC LIMIT 1) as last_message_at
       FROM conversations c
       JOIN users u ON u.id = CASE
         WHEN c.participant_a = $1 THEN c.participant_b
         ELSE c.participant_a
       END
       WHERE (c.participant_a = $1 OR c.participant_b = $1)
         AND u.deleted_at IS NULL
       ORDER BY last_message_at DESC NULLS LAST`,
      [req.userId]
    );
    res.json({ conversations: rows });
  } catch (err) {
    logger.error('conversations error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch conversations' });
  }
});

module.exports = router;
