require('dotenv').config();
const http = require('http');

const logger = require('./services/logger');
const { initDB } = require('./models/db');
const { initRedis } = require('./services/redis');
const { initWebSocket } = require('./services/websocket');
const { startCronJobs } = require('./services/cron');
const { createApp } = require('./app');

const app = createApp();
const server = http.createServer(app);

// ── Boot ─────────────────────────────────────────────────────────────────────
async function start() {
  try {
    await initDB();
    logger.info('PostgreSQL connected');

    await initRedis();
    logger.info('Redis connected');

    initWebSocket(server);
    logger.info('WebSocket initialized');

    startCronJobs();
    logger.info('Cron jobs started');

    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => {
      logger.info(`ROPE backend running on port ${PORT}`);
    });
  } catch (err) {
    logger.error('Startup failed', { error: err.message });
    process.exit(1);
  }
}

start();
