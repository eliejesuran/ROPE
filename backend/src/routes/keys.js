const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const { pool } = require('../models/db');
const logger = require('../services/logger');

router.use(authenticate);

// ── Upload key bundle ─────────────────────────────────────────────────────────
router.put('/bundle', async (req, res) => {
  try {
    const { ikPub, ikSigningPub, spkPub, spkSig, spkId, oneTimePreKeys } = req.body;
    if (!ikPub || !ikSigningPub || !spkPub || !spkSig || spkId === undefined) {
      return res.status(400).json({ error: 'ikPub, ikSigningPub, spkPub, spkSig, spkId required' });
    }

    await pool.query(
      `INSERT INTO device_keys (user_id, ik_pub, ik_signing_pub, spk_pub, spk_sig, spk_id)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (user_id) DO UPDATE SET
         ik_pub = EXCLUDED.ik_pub, ik_signing_pub = EXCLUDED.ik_signing_pub,
         spk_pub = EXCLUDED.spk_pub, spk_sig = EXCLUDED.spk_sig,
         spk_id = EXCLUDED.spk_id, updated_at = NOW()`,
      [req.userId, ikPub, ikSigningPub, spkPub, spkSig, spkId]
    );

    if (Array.isArray(oneTimePreKeys) && oneTimePreKeys.length > 0) {
      const values = oneTimePreKeys.map((_, i) => `($1, $${2 + i * 2}, $${3 + i * 2})`).join(', ');
      const params = [req.userId];
      oneTimePreKeys.forEach(({ id, pub }) => params.push(id, pub));
      await pool.query(
        `INSERT INTO one_time_prekeys (user_id, key_id, opk_pub) VALUES ${values} ON CONFLICT DO NOTHING`,
        params
      );
    }

    res.json({ success: true });
  } catch (err) {
    logger.error('keys/bundle upload error', { error: err.message });
    res.status(500).json({ error: 'Failed to upload key bundle' });
  }
});

// ── Fetch key bundle for a contact (consumes one OPK) ────────────────────────
router.get('/bundle/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const { rows: keyRows } = await pool.query(
      'SELECT ik_pub, ik_signing_pub, spk_pub, spk_sig, spk_id FROM device_keys WHERE user_id = $1',
      [userId]
    );
    if (keyRows.length === 0) return res.status(404).json({ error: 'No key bundle for this user' });

    // Atomically consume one OPK
    const { rows: opkRows } = await pool.query(
      `DELETE FROM one_time_prekeys
       WHERE id = (SELECT id FROM one_time_prekeys WHERE user_id = $1 ORDER BY key_id LIMIT 1)
       RETURNING key_id, opk_pub`,
      [userId]
    );

    const k = keyRows[0];
    res.json({
      userId,
      ikPub: k.ik_pub,
      ikSigningPub: k.ik_signing_pub,
      spkPub: k.spk_pub,
      spkSig: k.spk_sig,
      spkId: k.spk_id,
      opk: opkRows.length > 0 ? { id: opkRows[0].key_id, pub: opkRows[0].opk_pub } : null,
    });
  } catch (err) {
    logger.error('keys/bundle fetch error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch key bundle' });
  }
});

// ── Store X3DH init (Alice posts so Bob can derive SK) ────────────────────────
router.post('/x3dh-init', async (req, res) => {
  try {
    const { conversationId, ikPub, ekPub, opkId } = req.body;
    if (!conversationId || !ikPub || !ekPub) {
      return res.status(400).json({ error: 'conversationId, ikPub, ekPub required' });
    }

    // Requester must be a participant
    const { rows: convRows } = await pool.query(
      'SELECT id FROM conversations WHERE id = $1 AND (participant_a = $2 OR participant_b = $2)',
      [conversationId, req.userId]
    );
    if (convRows.length === 0) return res.status(403).json({ error: 'Forbidden' });

    // Store with DO NOTHING — first poster wins (avoids race-condition overwrites)
    const { rows } = await pool.query(
      `INSERT INTO x3dh_sessions (conversation_id, initiator_id, ik_pub, ek_pub, opk_id)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (conversation_id) DO NOTHING
       RETURNING conversation_id`,
      [conversationId, req.userId, ikPub, ekPub, opkId ?? null]
    );

    if (rows.length === 0) {
      // Another party already posted init — client should fetch it and become responder
      return res.status(409).json({ error: 'X3DH init already exists' });
    }

    res.json({ success: true });
  } catch (err) {
    logger.error('keys/x3dh-init post error', { error: err.message });
    res.status(500).json({ error: 'Failed to store X3DH init' });
  }
});

// ── Fetch X3DH init (Bob retrieves Alice's params) ────────────────────────────
router.get('/x3dh-init/:conversationId', async (req, res) => {
  try {
    const { conversationId } = req.params;

    // Requester must be a participant
    const { rows: convRows } = await pool.query(
      'SELECT id FROM conversations WHERE id = $1 AND (participant_a = $2 OR participant_b = $2)',
      [conversationId, req.userId]
    );
    if (convRows.length === 0) return res.status(403).json({ error: 'Forbidden' });

    const { rows } = await pool.query(
      'SELECT initiator_id, ik_pub, ek_pub, opk_id FROM x3dh_sessions WHERE conversation_id = $1',
      [conversationId]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'No X3DH init found' });

    const session = rows[0];
    // Initiator already has their SK — only the responder should receive this
    if (session.initiator_id === req.userId) {
      return res.status(404).json({ error: 'No X3DH init found' });
    }

    res.json({
      initiatorId: session.initiator_id,
      ikPub: session.ik_pub,
      ekPub: session.ek_pub,
      opkId: session.opk_id,
    });
  } catch (err) {
    logger.error('keys/x3dh-init get error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch X3DH init' });
  }
});

module.exports = router;
