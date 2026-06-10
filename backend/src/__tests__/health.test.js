const request = require('supertest');
const { createApp } = require('../app');

let app;
beforeAll(() => { app = createApp(); });

describe('GET /health', () => {
  it('returns ok with version and EU region', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok', version: '0.1.0', region: 'EU' });
  });
});

describe('Unknown route', () => {
  it('returns 404', async () => {
    const res = await request(app).get('/api/nonexistent');
    expect(res.status).toBe(404);
  });
});
