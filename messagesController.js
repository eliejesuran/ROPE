const { pool } = require('../models/db');
const { getIO } = require('../services/websocket');
const logger = require('../services/logger');

// ── Send a message ────────────────────────────────────────────────────────────
// The server ONLY receives ciphertext + IV. It cannot decrypt the message.
exports.sendMessage = async (req, res) => {
  try {
    const { conversationId, ciphertext, iv } = req.body;
    const senderId = req.userId;

    if (!conversationId || !ciphertext || !iv) {
      return res.status(400).json({ error: 'conversationId, ciphertext and iv are required' });
    }

    // Verify sender is a participant in this conversation
    const { rows: convRows } = await pool.query(
      `SELECT id, participant_a, participant_b FROM conversations
       WHERE id = $1 AND (participant_a = $2 OR participant_b = $2)`,
      [conversationId, senderId]
    );

    if (!convRows.length) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const conv = convRows[0];

    // Store ciphertext only — server is blind to content
    const { rows: msgRows } = await pool.query(
      `INSERT INTO messages (conversation_id, sender_id, ciphertext, iv)
       VALUES ($1, $2, $3, $4)
       RETURNING id, sent_at`,
      [conversationId, senderId, ciphertext, iv]
    );

    const message = msgRows[0];

    // Push to recipient via WebSocket
    const recipientId = conv.participant_a === senderId
      ? conv.participant_b
      : conv.participant_a;

    const io = getIO();
    io.to(`user:${recipientId}`).emit('message:new', {
      id: message.id,
      conversationId,
      senderId,
      ciphertext,
      iv,
      sentAt: message.sent_at,
    });

    logger.info('Message stored', { messageId: message.id, conversationId });

    res.status(201).json({ id: message.id, sentAt: message.sent_at });
  } catch (err) {
    logger.error('sendMessage error', { error: err.message });
    res.status(500).json({ error: 'Failed to send message' });
  }
};

// ── Get messages ──────────────────────────────────────────────────────────────
exports.getMessages = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { before, limit = 50 } = req.query;
    const userId = req.userId;

    // Verify access
    const { rows: convRows } = await pool.query(
      `SELECT id FROM conversations
       WHERE id = $1 AND (participant_a = $2 OR participant_b = $2)`,
      [conversationId, userId]
    );

    if (!convRows.length) return res.status(403).json({ error: 'Forbidden' });

    const { rows: messages } = await pool.query(
      `SELECT id, sender_id, ciphertext, iv, sent_at, delivered_at, read_at
       FROM messages
       WHERE conversation_id = $1
         AND deleted_at IS NULL
         ${before ? 'AND sent_at < $3' : ''}
       ORDER BY sent_at DESC
       LIMIT $2`,
      before ? [conversationId, Math.min(Number(limit), 100), before] : [conversationId, Math.min(Number(limit), 100)]
    );

    // Mark as delivered
    await pool.query(
      `UPDATE messages SET delivered_at = NOW()
       WHERE conversation_id = $1 AND sender_id != $2 AND delivered_at IS NULL`,
      [conversationId, userId]
    );

    res.json({ messages: messages.reverse() });
  } catch (err) {
    logger.error('getMessages error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
};

// ── Delete a message (GDPR right to erasure) ──────────────────────────────────
exports.deleteMessage = async (req, res) => {
  try {
    const { messageId } = req.params;
    const userId = req.userId;

    const { rowCount } = await pool.query(
      `UPDATE messages SET deleted_at = NOW(), ciphertext = '', iv = ''
       WHERE id = $1 AND sender_id = $2`,
      [messageId, userId]
    );

    if (!rowCount) return res.status(404).json({ error: 'Message not found or not yours' });

    res.json({ success: true });
  } catch (err) {
    logger.error('deleteMessage error', { error: err.message });
    res.status(500).json({ error: 'Failed to delete message' });
  }
};
