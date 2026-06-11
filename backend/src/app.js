const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const logger = require('./services/logger');

const authRoutes = require('./routes/auth');
const messageRoutes = require('./routes/messages');
const contactRoutes = require('./routes/contacts');
const accountRoutes = require('./routes/account');
const keysRoutes = require('./routes/keys');
const pushRoutes = require('./routes/push');

function createApp() {
  const app = express();

  app.use(helmet());
  app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }));

  if (process.env.NODE_ENV !== 'test') {
    app.use(rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 100,
      standardHeaders: true,
      legacyHeaders: false,
      message: { error: 'Too many requests, please try again later.' },
    }));
  }

  app.use(express.json({ limit: '10kb' }));

  app.get('/health', (req, res) => {
    res.json({ status: 'ok', version: '0.1.0', region: 'EU' });
  });

  app.use('/api/auth', authRoutes);
  app.use('/api/messages', messageRoutes);
  app.use('/api/contacts', contactRoutes);
  app.use('/api/account', accountRoutes);
  app.use('/api/keys', keysRoutes);
  app.use('/api/push', pushRoutes);

  app.use((req, res) => res.status(404).json({ error: 'Not found' }));

  app.use((err, req, res, next) => {
    logger.error('Unhandled error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

module.exports = { createApp };
