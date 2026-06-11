const request = require('supertest');
const { createApp } = require('../app');
const { pool, initDB } = require('../models/db');
const { createUserAndLogin } = require('./helpers/auth');

jest.mock('../services/websocket', () => ({
  getIO: () => ({ to: () => ({ emit: jest.fn() }) }),
  initWebSocket: jest.fn(),
  isOnline: jest.fn().mockReturnValue(false),
}));

jest.mock('../services/push', () => ({
  sendPushNotifications: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../services/redis', () => ({
  getRedis: () => ({ incr: jest.fn().mockResolvedValue(1), expire: jest.fn().mockResolvedValue(1) }),
  initRedis: jest.fn(),
}));

let app;

beforeAll(async () => {
  await initDB();
  app = createApp();
});

beforeEach(async () => {
  await pool.query('DELETE FROM device_tokens');
  await pool.query('DELETE FROM otp_codes');
  await pool.query('DELETE FROM users');
});

describe('POST /api/push/register', () => {
  it('registers an iOS push token', async () => {
    const { token } = await createUserAndLogin(app, '+32471111111');
    const expoToken = 'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]';

    const res = await request(app)
      .post('/api/push/register')
      .set('Authorization', `Bearer ${token}`)
      .send({ token: expoToken, platform: 'ios' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const { rows } = await pool.query('SELECT * FROM device_tokens WHERE token = $1', [expoToken]);
    expect(rows).toHaveLength(1);
    expect(rows[0].platform).toBe('ios');
  });

  it('upserts on re-register with same token', async () => {
    const { token: tokenA, user: userA } = await createUserAndLogin(app, '+32471111111');
    const { token: tokenB } = await createUserAndLogin(app, '+32472222222');
    const expoToken = 'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]';

    await request(app)
      .post('/api/push/register')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ token: expoToken, platform: 'ios' });

    const res = await request(app)
      .post('/api/push/register')
      .set('Authorization', `Bearer ${tokenB}`)
      .send({ token: expoToken, platform: 'android' });

    expect(res.status).toBe(200);
    const { rows } = await pool.query('SELECT * FROM device_tokens WHERE token = $1', [expoToken]);
    expect(rows).toHaveLength(1);
  });

  it('rejects invalid platform', async () => {
    const { token } = await createUserAndLogin(app, '+32471111111');

    const res = await request(app)
      .post('/api/push/register')
      .set('Authorization', `Bearer ${token}`)
      .send({ token: 'ExponentPushToken[abc]', platform: 'windows' });

    expect(res.status).toBe(400);
  });

  it('requires authentication', async () => {
    const res = await request(app)
      .post('/api/push/register')
      .send({ token: 'ExponentPushToken[abc]', platform: 'ios' });
    expect(res.status).toBe(401);
  });
});

describe('DELETE /api/push/unregister', () => {
  it('removes a registered token', async () => {
    const { token } = await createUserAndLogin(app, '+32471111111');
    const expoToken = 'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]';

    await request(app)
      .post('/api/push/register')
      .set('Authorization', `Bearer ${token}`)
      .send({ token: expoToken, platform: 'ios' });

    const res = await request(app)
      .delete('/api/push/unregister')
      .set('Authorization', `Bearer ${token}`)
      .send({ token: expoToken });

    expect(res.status).toBe(200);
    const { rows } = await pool.query('SELECT * FROM device_tokens WHERE token = $1', [expoToken]);
    expect(rows).toHaveLength(0);
  });

  it('requires authentication', async () => {
    const res = await request(app)
      .delete('/api/push/unregister')
      .send({ token: 'ExponentPushToken[abc]' });
    expect(res.status).toBe(401);
  });
});
