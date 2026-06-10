const request = require('supertest');
const { createApp } = require('../app');
const { pool, initDB } = require('../models/db');
const { createUserAndLogin, TEST_PUBLIC_KEY } = require('./helpers/auth');

jest.mock('../services/websocket', () => ({
  getIO: () => ({ to: () => ({ emit: jest.fn() }) }),
  initWebSocket: jest.fn(),
}));

const mockRedis = {
  incr: jest.fn().mockResolvedValue(1),
  expire: jest.fn().mockResolvedValue(1),
};
jest.mock('../services/redis', () => ({
  getRedis: () => mockRedis,
  initRedis: jest.fn(),
}));

let app;

beforeAll(async () => {
  await initDB();
  app = createApp();
});

beforeEach(async () => {
  mockRedis.incr.mockResolvedValue(1);
  mockRedis.expire.mockResolvedValue(1);
  await pool.query('DELETE FROM otp_codes');
  await pool.query('DELETE FROM users');
});

// ── Request OTP ───────────────────────────────────────────────────────────────

describe('POST /api/auth/request-otp', () => {
  it('accepts a valid E.164 phone and returns devCode in bypass mode', async () => {
    const res = await request(app)
      .post('/api/auth/request-otp')
      .send({ phone: '+32471234567' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.expiresIn).toBe(300);
    expect(res.body.devCode).toBe('123456');
  });

  it('strips spaces and dashes from phone number', async () => {
    const res = await request(app)
      .post('/api/auth/request-otp')
      .send({ phone: '+32 471 234 567' });
    expect(res.status).toBe(200);
  });

  it('rejects a phone without + prefix', async () => {
    const res = await request(app)
      .post('/api/auth/request-otp')
      .send({ phone: '0471234567' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/Invalid phone/);
  });

  it('rejects a missing phone field', async () => {
    const res = await request(app)
      .post('/api/auth/request-otp')
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Phone number required');
  });

  it('rate-limits after 5 OTP requests in 10 minutes', async () => {
    mockRedis.incr.mockResolvedValueOnce(6);

    const res = await request(app)
      .post('/api/auth/request-otp')
      .send({ phone: '+32471234567' });

    expect(res.status).toBe(429);
    expect(res.body.error).toMatch(/Too many OTP requests/);
  });
});

// ── Verify OTP ────────────────────────────────────────────────────────────────

describe('POST /api/auth/verify-otp', () => {
  const phone = '+32471234567';

  beforeEach(async () => {
    await request(app).post('/api/auth/request-otp').send({ phone });
  });

  it('returns a JWT and user info on correct OTP', async () => {
    const res = await request(app)
      .post('/api/auth/verify-otp')
      .send({ phone, code: '123456', publicKey: TEST_PUBLIC_KEY });

    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.user.phoneLast4).toBe('4567');
    expect(res.body.user.id).toBeDefined();
    // Server must never echo the full phone number
    expect(JSON.stringify(res.body)).not.toContain('32471234567');
  });

  it('rejects a wrong OTP code', async () => {
    const res = await request(app)
      .post('/api/auth/verify-otp')
      .send({ phone, code: '000000', publicKey: TEST_PUBLIC_KEY });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid or expired code');
  });

  it('OTP cannot be reused after successful login', async () => {
    await request(app)
      .post('/api/auth/verify-otp')
      .send({ phone, code: '123456', publicKey: TEST_PUBLIC_KEY });

    const res = await request(app)
      .post('/api/auth/verify-otp')
      .send({ phone, code: '123456', publicKey: TEST_PUBLIC_KEY });

    expect(res.status).toBe(401);
  });

  it('rejects when phone, code, or publicKey is missing', async () => {
    const res = await request(app)
      .post('/api/auth/verify-otp')
      .send({ phone, code: '123456' }); // missing publicKey

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/);
  });

  it('second login with same phone updates publicKey (upsert)', async () => {
    const newKey = Buffer.from('rope-new-public-key-32bytes-xxxxx').toString('base64');

    await request(app)
      .post('/api/auth/verify-otp')
      .send({ phone, code: '123456', publicKey: TEST_PUBLIC_KEY });

    // Request a second OTP and re-login with a new public key
    await pool.query('DELETE FROM otp_codes');
    await request(app).post('/api/auth/request-otp').send({ phone });
    const res = await request(app)
      .post('/api/auth/verify-otp')
      .send({ phone, code: '123456', publicKey: newKey });

    expect(res.status).toBe(200);
    const { rows } = await pool.query('SELECT public_key FROM users WHERE phone_last4 = $1', ['4567']);
    expect(rows[0].public_key).toBe(newKey);
  });
});

// ── Refresh token ─────────────────────────────────────────────────────────────

describe('POST /api/auth/refresh', () => {
  it('issues a new valid JWT for a valid token', async () => {
    const { token } = await createUserAndLogin(app, '+32471234567');

    const res = await request(app)
      .post('/api/auth/refresh')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    // JWT structure: header.payload.signature
    expect(res.body.token.split('.')).toHaveLength(3);
  });

  it('rejects an invalid token', async () => {
    const res = await request(app)
      .post('/api/auth/refresh')
      .set('Authorization', 'Bearer not.a.real.token');

    expect(res.status).toBe(401);
  });

  it('rejects a missing Authorization header', async () => {
    const res = await request(app).post('/api/auth/refresh');
    expect(res.status).toBe(401);
  });
});
