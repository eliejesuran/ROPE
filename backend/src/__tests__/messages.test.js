const request = require('supertest');
const { createApp } = require('../app');
const { pool, initDB } = require('../models/db');
const { createUserAndLogin } = require('./helpers/auth');

jest.mock('../services/websocket', () => ({
  getIO: () => ({ to: () => ({ emit: jest.fn() }) }),
  initWebSocket: jest.fn(),
}));

let app;
let userA, userB, conversationId;

beforeAll(async () => {
  await initDB();
  app = createApp();
});

beforeEach(async () => {
  await pool.query('DELETE FROM otp_codes');
  await pool.query('DELETE FROM users'); // cascades conversations + messages

  userA = await createUserAndLogin(app, '+32471111111');
  userB = await createUserAndLogin(app, '+32472222222');

  const res = await request(app)
    .post('/api/contacts/find')
    .set('Authorization', `Bearer ${userA.token}`)
    .send({ phone: '+32472222222' });
  conversationId = res.body.conversationId;
});

// ── Send message ──────────────────────────────────────────────────────────────

describe('POST /api/messages', () => {
  it('stores ciphertext and returns id + sentAt', async () => {
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ conversationId, ciphertext: 'dGVzdC1jaXBoZXJ0ZXh0', iv: 'dGVzdC1pdg==' });

    expect(res.status).toBe(201);
    expect(res.body.id).toBeDefined();
    expect(res.body.sentAt).toBeDefined();
  });

  it('server never stores or returns plaintext', async () => {
    const plaintext = 'super secret message';
    // Simulate: in real app, ciphertext would be AES-encrypted; here we use a string
    // that happens to not be the plaintext to verify server blindness
    const fakeCiphertext = Buffer.from('encrypted:' + plaintext).toString('base64');

    const sendRes = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ conversationId, ciphertext: fakeCiphertext, iv: 'dGVzdA==' });

    const getRes = await request(app)
      .get(`/api/messages/${conversationId}`)
      .set('Authorization', `Bearer ${userA.token}`);

    // The plaintext must never appear decoded in any field
    expect(JSON.stringify(getRes.body)).not.toContain(plaintext);
    // The ciphertext stored matches exactly what was sent (no transform)
    expect(getRes.body.messages[0].ciphertext).toBe(fakeCiphertext);
  });

  it('rejects missing conversationId, ciphertext, or iv', async () => {
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ conversationId, ciphertext: 'abc' }); // missing iv

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/);
  });

  it('returns 403 for a conversation the user is not part of', async () => {
    const userC = await createUserAndLogin(app, '+32473333333');
    const convBC = await request(app)
      .post('/api/contacts/find')
      .set('Authorization', `Bearer ${userB.token}`)
      .send({ phone: '+32473333333' });

    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ conversationId: convBC.body.conversationId, ciphertext: 'xxx', iv: 'yyy' });

    expect(res.status).toBe(403);
  });

  it('requires authentication', async () => {
    const res = await request(app)
      .post('/api/messages')
      .send({ conversationId, ciphertext: 'abc', iv: 'def' });
    expect(res.status).toBe(401);
  });
});

// ── Get messages ──────────────────────────────────────────────────────────────

describe('GET /api/messages/:conversationId', () => {
  beforeEach(async () => {
    await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ conversationId, ciphertext: 'bXNnMQ==', iv: 'aXYx' });
  });

  it('returns messages in chronological order', async () => {
    await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ conversationId, ciphertext: 'bXNnMg==', iv: 'aXYy' });

    const res = await request(app)
      .get(`/api/messages/${conversationId}`)
      .set('Authorization', `Bearer ${userA.token}`);

    expect(res.status).toBe(200);
    expect(res.body.messages).toHaveLength(2);
    // First message should be oldest
    const times = res.body.messages.map(m => new Date(m.sent_at).getTime());
    expect(times[0]).toBeLessThanOrEqual(times[1]);
  });

  it('marks messages as delivered when recipient fetches', async () => {
    // getMessages runs SELECT then UPDATE — response reflects pre-update state.
    // Verify the delivery flag in DB after the fetch, not in the response body.
    await request(app)
      .get(`/api/messages/${conversationId}`)
      .set('Authorization', `Bearer ${userB.token}`);

    const { rows } = await pool.query(
      `SELECT delivered_at FROM messages WHERE conversation_id = $1 AND sender_id = $2`,
      [conversationId, userA.user.id]
    );
    expect(rows[0].delivered_at).not.toBeNull();
  });

  it('does not mark own messages as delivered (only recipient marks delivery)', async () => {
    const res = await request(app)
      .get(`/api/messages/${conversationId}`)
      .set('Authorization', `Bearer ${userA.token}`);

    expect(res.status).toBe(200);
    // A fetching their own sent messages should NOT mark them delivered
    expect(res.body.messages[0].delivered_at).toBeNull();
  });

  it('respects the limit query param (max 100)', async () => {
    const res = await request(app)
      .get(`/api/messages/${conversationId}?limit=1`)
      .set('Authorization', `Bearer ${userA.token}`);

    expect(res.status).toBe(200);
    expect(res.body.messages).toHaveLength(1);
  });

  it('returns 403 if user is not a participant', async () => {
    const userC = await createUserAndLogin(app, '+32473333333');
    const res = await request(app)
      .get(`/api/messages/${conversationId}`)
      .set('Authorization', `Bearer ${userC.token}`);

    expect(res.status).toBe(403);
  });

  it('requires authentication', async () => {
    const res = await request(app).get(`/api/messages/${conversationId}`);
    expect(res.status).toBe(401);
  });
});

// ── Delete message ────────────────────────────────────────────────────────────

describe('DELETE /api/messages/:messageId', () => {
  let messageId;

  beforeEach(async () => {
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ conversationId, ciphertext: 'dGVzdA==', iv: 'aXY=' });
    messageId = res.body.id;
  });

  it('allows sender to delete their own message (erases content)', async () => {
    const res = await request(app)
      .delete(`/api/messages/${messageId}`)
      .set('Authorization', `Bearer ${userA.token}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    // Verify ciphertext is erased in DB
    const { rows } = await pool.query('SELECT ciphertext, deleted_at FROM messages WHERE id = $1', [messageId]);
    expect(rows[0].ciphertext).toBe('');
    expect(rows[0].deleted_at).not.toBeNull();
  });

  it('returns 404 when trying to delete another user\'s message', async () => {
    const res = await request(app)
      .delete(`/api/messages/${messageId}`)
      .set('Authorization', `Bearer ${userB.token}`);

    expect(res.status).toBe(404);
  });

  it('deleted messages are excluded from GET results', async () => {
    await request(app)
      .delete(`/api/messages/${messageId}`)
      .set('Authorization', `Bearer ${userA.token}`);

    const res = await request(app)
      .get(`/api/messages/${conversationId}`)
      .set('Authorization', `Bearer ${userA.token}`);

    expect(res.body.messages).toHaveLength(0);
  });

  it('requires authentication', async () => {
    const res = await request(app).delete(`/api/messages/${messageId}`);
    expect(res.status).toBe(401);
  });
});
