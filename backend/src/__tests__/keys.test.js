const request = require('supertest');
const { createApp } = require('../app');
const { pool, initDB } = require('../models/db');
const { createUserAndLogin } = require('./helpers/auth');

jest.mock('../services/websocket', () => ({
  getIO: () => ({ to: () => ({ emit: jest.fn() }) }),
  initWebSocket: jest.fn(),
  isOnline: jest.fn().mockReturnValue(true),
}));

jest.mock('../services/redis', () => ({
  getRedis: () => ({ incr: jest.fn().mockResolvedValue(1), expire: jest.fn().mockResolvedValue(1) }),
  initRedis: jest.fn(),
}));

let app;

const BUNDLE = {
  ikPub:        'aWtQdWI=',
  ikSigningPub: 'aWtTaWduaW5nUHVi',
  spkPub:       'c3BrUHVi',
  spkSig:       'c3BrU2ln',
  spkId:        1,
  oneTimePreKeys: [
    { id: 1, pub: 'b3BrMQ==' },
    { id: 2, pub: 'b3BrMg==' },
  ],
};

beforeAll(async () => {
  await initDB();
  app = createApp();
});

beforeEach(async () => {
  await pool.query('DELETE FROM x3dh_sessions');
  await pool.query('DELETE FROM one_time_prekeys');
  await pool.query('DELETE FROM device_keys');
  await pool.query('DELETE FROM messages');
  await pool.query('DELETE FROM conversations');
  await pool.query('DELETE FROM otp_codes');
  await pool.query('DELETE FROM users');
});

// ── PUT /api/keys/bundle ──────────────────────────────────────────────────────

describe('PUT /api/keys/bundle', () => {
  it('uploads key bundle for authenticated user', async () => {
    const { token } = await createUserAndLogin(app, '+32471000001');
    const res = await request(app)
      .put('/api/keys/bundle')
      .set('Authorization', `Bearer ${token}`)
      .send(BUNDLE);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('upserts on re-upload with new keys', async () => {
    const { token } = await createUserAndLogin(app, '+32471000001');
    await request(app).put('/api/keys/bundle').set('Authorization', `Bearer ${token}`).send(BUNDLE);

    const updated = { ...BUNDLE, ikPub: 'bmV3SWtQdWI=', oneTimePreKeys: [] };
    const res = await request(app)
      .put('/api/keys/bundle')
      .set('Authorization', `Bearer ${token}`)
      .send(updated);
    expect(res.status).toBe(200);

    const { rows } = await pool.query('SELECT ik_pub FROM device_keys');
    expect(rows[0].ik_pub).toBe('bmV3SWtQdWI=');
  });

  it('returns 400 if required fields are missing', async () => {
    const { token } = await createUserAndLogin(app, '+32471000001');
    const res = await request(app)
      .put('/api/keys/bundle')
      .set('Authorization', `Bearer ${token}`)
      .send({ ikPub: 'abc' });
    expect(res.status).toBe(400);
  });

  it('requires authentication', async () => {
    const res = await request(app).put('/api/keys/bundle').send(BUNDLE);
    expect(res.status).toBe(401);
  });
});

// ── GET /api/keys/bundle/:userId ──────────────────────────────────────────────

describe('GET /api/keys/bundle/:userId', () => {
  it('returns bundle with one OPK and consumes it', async () => {
    const { token: aliceToken, user: alice } = await createUserAndLogin(app, '+32471000001');
    const { token: bobToken } = await createUserAndLogin(app, '+32471000002');

    await request(app)
      .put('/api/keys/bundle')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send(BUNDLE);

    const res = await request(app)
      .get(`/api/keys/bundle/${alice.id}`)
      .set('Authorization', `Bearer ${bobToken}`);

    expect(res.status).toBe(200);
    expect(res.body.ikPub).toBe(BUNDLE.ikPub);
    expect(res.body.opk).not.toBeNull();
    expect(res.body.opk.id).toBe(1);

    // OPK 1 consumed — next fetch returns OPK 2
    const res2 = await request(app)
      .get(`/api/keys/bundle/${alice.id}`)
      .set('Authorization', `Bearer ${bobToken}`);
    expect(res2.body.opk.id).toBe(2);

    // All OPKs consumed — no more
    const res3 = await request(app)
      .get(`/api/keys/bundle/${alice.id}`)
      .set('Authorization', `Bearer ${bobToken}`);
    expect(res3.body.opk).toBeNull();
  });

  it('returns bundle without OPK when pool is empty', async () => {
    const { token: aliceToken, user: alice } = await createUserAndLogin(app, '+32471000001');
    const { token: bobToken } = await createUserAndLogin(app, '+32471000002');

    await request(app)
      .put('/api/keys/bundle')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({ ...BUNDLE, oneTimePreKeys: [] });

    const res = await request(app)
      .get(`/api/keys/bundle/${alice.id}`)
      .set('Authorization', `Bearer ${bobToken}`);

    expect(res.status).toBe(200);
    expect(res.body.opk).toBeNull();
  });

  it('returns 404 if no bundle exists for user', async () => {
    const { token } = await createUserAndLogin(app, '+32471000001');
    const { user: stranger } = await createUserAndLogin(app, '+32471000002');

    const res = await request(app)
      .get(`/api/keys/bundle/${stranger.id}`)
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
  });

  it('requires authentication', async () => {
    const res = await request(app).get('/api/keys/bundle/some-uuid');
    expect(res.status).toBe(401);
  });
});

// ── POST /api/keys/x3dh-init ─────────────────────────────────────────────────

describe('POST /api/keys/x3dh-init', () => {
  async function makeConversation(aliceId, bobId) {
    const [a, b] = [aliceId, bobId].sort();
    const { rows } = await pool.query(
      'INSERT INTO conversations (participant_a, participant_b) VALUES ($1, $2) RETURNING id',
      [a, b]
    );
    return rows[0].id;
  }

  it('stores X3DH init for a conversation', async () => {
    const { token: aliceToken, user: alice } = await createUserAndLogin(app, '+32471000001');
    const { user: bob } = await createUserAndLogin(app, '+32471000002');
    const convId = await makeConversation(alice.id, bob.id);

    const res = await request(app)
      .post('/api/keys/x3dh-init')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({ conversationId: convId, ikPub: 'aWtQdWI=', ekPub: 'ZWtQdWI=', opkId: 1 });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('returns 409 if init already exists', async () => {
    const { token: aliceToken, user: alice } = await createUserAndLogin(app, '+32471000001');
    const { user: bob } = await createUserAndLogin(app, '+32471000002');
    const convId = await makeConversation(alice.id, bob.id);

    const payload = { conversationId: convId, ikPub: 'aWtQdWI=', ekPub: 'ZWtQdWI=', opkId: null };
    await request(app).post('/api/keys/x3dh-init').set('Authorization', `Bearer ${aliceToken}`).send(payload);

    const res = await request(app)
      .post('/api/keys/x3dh-init')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send(payload);
    expect(res.status).toBe(409);
  });

  it('returns 403 if user is not a participant', async () => {
    const { user: alice } = await createUserAndLogin(app, '+32471000001');
    const { user: bob } = await createUserAndLogin(app, '+32471000002');
    const { token: eveToken } = await createUserAndLogin(app, '+32471000003');
    const convId = await makeConversation(alice.id, bob.id);

    const res = await request(app)
      .post('/api/keys/x3dh-init')
      .set('Authorization', `Bearer ${eveToken}`)
      .send({ conversationId: convId, ikPub: 'x', ekPub: 'y', opkId: null });
    expect(res.status).toBe(403);
  });

  it('requires authentication', async () => {
    const res = await request(app).post('/api/keys/x3dh-init').send({});
    expect(res.status).toBe(401);
  });
});

// ── GET /api/keys/status ──────────────────────────────────────────────────────

describe('GET /api/keys/status', () => {
  it('returns opkCount 0 and null spkId when no bundle uploaded', async () => {
    const { token } = await createUserAndLogin(app, '+32471000001');

    const res = await request(app)
      .get('/api/keys/status')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.opkCount).toBe(0);
    expect(res.body.spkId).toBeNull();
    expect(res.body.spkCreatedAt).toBeNull();
  });

  it('returns correct opkCount and spkId after bundle upload', async () => {
    const { token } = await createUserAndLogin(app, '+32471000001');

    await request(app)
      .put('/api/keys/bundle')
      .set('Authorization', `Bearer ${token}`)
      .send(BUNDLE);

    const res = await request(app)
      .get('/api/keys/status')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.opkCount).toBe(2);
    expect(res.body.spkId).toBe(1);
    expect(res.body.spkCreatedAt).not.toBeNull();
  });

  it('requires authentication', async () => {
    const res = await request(app).get('/api/keys/status');
    expect(res.status).toBe(401);
  });
});

// ── GET /api/keys/x3dh-init/:conversationId ──────────────────────────────────

describe('GET /api/keys/x3dh-init/:conversationId', () => {
  it('returns X3DH init for the responder (not the initiator)', async () => {
    const { token: aliceToken, user: alice } = await createUserAndLogin(app, '+32471000001');
    const { token: bobToken, user: bob } = await createUserAndLogin(app, '+32471000002');
    const [a, b] = [alice.id, bob.id].sort();
    const { rows } = await pool.query(
      'INSERT INTO conversations (participant_a, participant_b) VALUES ($1, $2) RETURNING id',
      [a, b]
    );
    const convId = rows[0].id;

    await request(app)
      .post('/api/keys/x3dh-init')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({ conversationId: convId, ikPub: 'aWtQdWI=', ekPub: 'ZWtQdWI=', opkId: 1 });

    // Bob (responder) can fetch
    const bobRes = await request(app)
      .get(`/api/keys/x3dh-init/${convId}`)
      .set('Authorization', `Bearer ${bobToken}`);
    expect(bobRes.status).toBe(200);
    expect(bobRes.body.ikPub).toBe('aWtQdWI=');
    expect(bobRes.body.opkId).toBe(1);

    // Alice (initiator) gets 404 — she already has her SK
    const aliceRes = await request(app)
      .get(`/api/keys/x3dh-init/${convId}`)
      .set('Authorization', `Bearer ${aliceToken}`);
    expect(aliceRes.status).toBe(404);
  });

  it('returns 404 if no X3DH init exists yet', async () => {
    const { token, user: u1 } = await createUserAndLogin(app, '+32471000001');
    const { user: u2 } = await createUserAndLogin(app, '+32471000002');
    const [a, b] = [u1.id, u2.id].sort();
    const { rows } = await pool.query(
      'INSERT INTO conversations (participant_a, participant_b) VALUES ($1, $2) RETURNING id',
      [a, b]
    );
    const res = await request(app)
      .get(`/api/keys/x3dh-init/${rows[0].id}`)
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
  });

  it('returns 403 if user is not a participant', async () => {
    const { user: alice } = await createUserAndLogin(app, '+32471000001');
    const { user: bob } = await createUserAndLogin(app, '+32471000002');
    const { token: eveToken } = await createUserAndLogin(app, '+32471000003');
    const [a, b] = [alice.id, bob.id].sort();
    const { rows } = await pool.query(
      'INSERT INTO conversations (participant_a, participant_b) VALUES ($1, $2) RETURNING id',
      [a, b]
    );
    const res = await request(app)
      .get(`/api/keys/x3dh-init/${rows[0].id}`)
      .set('Authorization', `Bearer ${eveToken}`);
    expect(res.status).toBe(403);
  });

  it('requires authentication', async () => {
    const res = await request(app).get('/api/keys/x3dh-init/some-uuid');
    expect(res.status).toBe(401);
  });
});
