const request = require('supertest');
const { createApp } = require('../app');
const { pool, initDB } = require('../models/db');
const { createUserAndLogin } = require('./helpers/auth');

jest.mock('../services/websocket', () => ({
  getIO: () => ({ to: () => ({ emit: jest.fn() }) }),
  initWebSocket: jest.fn(),
}));

let app;
let userA, userB;

beforeAll(async () => {
  await initDB();
  app = createApp();
});

beforeEach(async () => {
  await pool.query('DELETE FROM otp_codes');
  await pool.query('DELETE FROM users'); // cascades conversations + messages
  userA = await createUserAndLogin(app, '+32471111111');
  userB = await createUserAndLogin(app, '+32472222222');
});

// ── Find contact ──────────────────────────────────────────────────────────────

describe('POST /api/contacts/find', () => {
  it('finds a registered user and creates a conversation', async () => {
    const res = await request(app)
      .post('/api/contacts/find')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ phone: '+32472222222' });

    expect(res.status).toBe(200);
    expect(res.body.user.phoneLast4).toBe('2222');
    expect(res.body.user.publicKey).toBeDefined();
    expect(res.body.conversationId).toBeDefined();
  });

  it('is idempotent — repeated calls return the same conversationId', async () => {
    const r1 = await request(app)
      .post('/api/contacts/find')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ phone: '+32472222222' });

    const r2 = await request(app)
      .post('/api/contacts/find')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ phone: '+32472222222' });

    expect(r1.body.conversationId).toBe(r2.body.conversationId);
  });

  it('conversation order is canonical (A finds B = B finds A → same conv)', async () => {
    const fromA = await request(app)
      .post('/api/contacts/find')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ phone: '+32472222222' });

    const fromB = await request(app)
      .post('/api/contacts/find')
      .set('Authorization', `Bearer ${userB.token}`)
      .send({ phone: '+32471111111' });

    expect(fromA.body.conversationId).toBe(fromB.body.conversationId);
  });

  it('returns 404 for an unregistered phone number', async () => {
    const res = await request(app)
      .post('/api/contacts/find')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ phone: '+32479999999' });

    expect(res.status).toBe(404);
  });

  it('returns 404 when searching your own number', async () => {
    const res = await request(app)
      .post('/api/contacts/find')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ phone: '+32471111111' });

    expect(res.status).toBe(404);
  });

  it('never exposes the full phone number in the response (GDPR)', async () => {
    const res = await request(app)
      .post('/api/contacts/find')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ phone: '+32472222222' });

    const body = JSON.stringify(res.body);
    expect(body).not.toContain('+32472222222');
    expect(body).not.toContain('32472222222');
  });

  it('requires authentication', async () => {
    const res = await request(app)
      .post('/api/contacts/find')
      .send({ phone: '+32472222222' });
    expect(res.status).toBe(401);
  });

  it('returns 400 when phone field is missing', async () => {
    const res = await request(app)
      .post('/api/contacts/find')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({});
    expect(res.status).toBe(400);
  });
});

// ── List conversations ────────────────────────────────────────────────────────

describe('GET /api/contacts/conversations', () => {
  beforeEach(async () => {
    await request(app)
      .post('/api/contacts/find')
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ phone: '+32472222222' });
  });

  it('returns the conversation list for the authenticated user', async () => {
    const res = await request(app)
      .get('/api/contacts/conversations')
      .set('Authorization', `Bearer ${userA.token}`);

    expect(res.status).toBe(200);
    expect(res.body.conversations).toHaveLength(1);
    expect(res.body.conversations[0].phone_last4).toBe('2222');
  });

  it('does not show deleted users in the list', async () => {
    await request(app)
      .delete('/api/account')
      .set('Authorization', `Bearer ${userB.token}`);

    const res = await request(app)
      .get('/api/contacts/conversations')
      .set('Authorization', `Bearer ${userA.token}`);

    expect(res.status).toBe(200);
    expect(res.body.conversations).toHaveLength(0);
  });

  it('requires authentication', async () => {
    const res = await request(app).get('/api/contacts/conversations');
    expect(res.status).toBe(401);
  });
});
