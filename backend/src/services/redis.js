const { createClient } = require('redis');
const logger = require('./logger');

let client;

async function initRedis() {
  client = createClient({ url: process.env.REDIS_URL });
  client.on('error', (err) => logger.error('Redis error', { error: err.message }));
  await client.connect();
  return client;
}

function getRedis() {
  if (!client) throw new Error('Redis not initialised');
  return client;
}

module.exports = { initRedis, getRedis };
