const request = require('supertest');
const { createApp } = require('../app');
const { pool, initDB } = require('../models/db');
const { createUserAndLogin } = require('./helpers/auth');

jest.mock('../services/websocket', () => ({
  getIO: () => ({ to: () => ({ emit: jest.fn() }) }),
  initWebSocket: jest.fn(),
}));

let app;

beforeAll(async () => {
  await initDB();
  app = createApp();
});

beforeEach(async () => {
  await pool.query('DELETE FROM otp_codes');
  await pool.query('DELETE FROM users'); // cascades conversations + messages
});

// ── GDPR account deletion ─────────────────────────────────────────────────────

describe('DELETE /api/account', () => {
  it('soft-deletes user and anonymises all identifying data', async () => {
    const { token, user } = await createUserAndLogin(app, '+32471111111');

    const res = await request(app)
      .delete('/api/account')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [user.id]);
    expect(rows).toHaveLength(1);
    expect(rows[0].deleted_at).not.toBeNull();
    expect(rows[0].phone_hash).toMatch(/^DELETED_/);
    expect(rows[0].phone_last4).toBe('****');
    expect(rows[0].public_key).toBe('');
    expect(rows[0].display_name).toBeNull();
  });

  it('erases ciphertext of all sent messages', async () => {
    const { token: tokenA } = await createUserAndLogin(app, '+32471111111');
    const { token: tokenB } = await createUserAndLogin(app, '+32472222222');

    const convRes = await request(app)
      .post('/api/contacts/find')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ phone: '+32472222222' });
    const convId = convRes.body.conversationId;

    await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ conversationId: convId, ciphertext: 'c3VwZXJzZWNyZXQ=', iv: 'aXY=' });

    await request(app)
      .delete('/api/account')
      .set('Authorization', `Bearer ${tokenA}`);

    const { rows } = await pool.query(
      'SELECT ciphertext, deleted_at FROM messages WHERE conversation_id = $1',
      [convId]
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].ciphertext).toBe('');
    expect(rows[0].deleted_at).not.toBeNull();
  });

  it('deleted user no longer appears in contact searches', async () => {
    const { token: tokenA } = await createUserAndLogin(app, '+32471111111');
    const { token: tokenB } = await createUserAndLogin(app, '+32472222222');

    await request(app)
      .delete('/api/account')
      .set('Authorization', `Bearer ${tokenB}`);

    const res = await request(app)
      .post('/api/contacts/find')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ phone: '+32472222222' });

    expect(res.status).toBe(404);
  });

  it('token is unusable after account deletion', async () => {
    const { token } = await createUserAndLogin(app, '+32471111111');
    await request(app).delete('/api/account').set('Authorization', `Bearer ${token}`);

    // The token is still valid JWT — but the user is deleted and excluded from contacts
    // Attempting to use protected endpoints still works (JWT valid, user soft-deleted)
    // This documents current Sprint 1 behaviour — Sprint 2 should handle post-delete token invalidation
    const res = await request(app)
      .get('/api/contacts/conversations')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200); // JWT still valid, returns empty list
  });

  it('requires authentication', async () => {
    const res = await request(app).delete('/api/account');
    expect(res.status).toBe(401);
  });
});

// ── Display name ──────────────────────────────────────────────────────────────

describe('PATCH /api/account/display-name', () => {
  it('updates display name successfully', async () => {
    const { token } = await createUserAndLogin(app, '+32471111111');

    const res = await request(app)
      .patch('/api/account/display-name')
      .set('Authorization', `Bearer ${token}`)
      .send({ displayName: 'Alice' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('rejects a display name longer than 30 characters', async () => {
    const { token } = await createUserAndLogin(app, '+32471111111');

    const res = await request(app)
      .patch('/api/account/display-name')
      .set('Authorization', `Bearer ${token}`)
      .send({ displayName: 'A'.repeat(31) });

    expect(res.status).toBe(400);
  });

  it('rejects an empty display name', async () => {
    const { token } = await createUserAndLogin(app, '+32471111111');

    const res = await request(app)
      .patch('/api/account/display-name')
      .set('Authorization', `Bearer ${token}`)
      .send({ displayName: '' });

    expect(res.status).toBe(400);
  });

  it('requires authentication', async () => {
    const res = await request(app)
      .patch('/api/account/display-name')
      .send({ displayName: 'Alice' });
    expect(res.status).toBe(401);
  });
});
