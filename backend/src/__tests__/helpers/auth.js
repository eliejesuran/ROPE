const request = require('supertest');

const TEST_PUBLIC_KEY = Buffer.from('rope-test-public-key-32bytes-pad').toString('base64');

async function createUserAndLogin(app, phone) {
  await request(app).post('/api/auth/request-otp').send({ phone });
  const res = await request(app)
    .post('/api/auth/verify-otp')
    .send({ phone, code: '123456', publicKey: TEST_PUBLIC_KEY });

  if (res.status !== 200) {
    throw new Error(`Login failed for ${phone}: ${JSON.stringify(res.body)}`);
  }
  return { token: res.body.token, user: res.body.user };
}

module.exports = { createUserAndLogin, TEST_PUBLIC_KEY };
