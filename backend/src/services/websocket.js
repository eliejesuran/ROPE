const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const logger = require('./logger');

let io;

function initWebSocket(server) {
  io = new Server(server, {
    cors: { origin: '*', methods: ['GET', 'POST'] },
    pingTimeout: 60000,
    pingInterval: 25000,
  });

  // JWT authentication for WebSocket
  io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('Authentication required'));

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      socket.userId = decoded.sub;
      next();
    } catch {
      next(new Error('Invalid token'));
    }
  });

  io.on('connection', (socket) => {
    // Each user joins their own room for targeted delivery
    socket.join(`user:${socket.userId}`);
    logger.info('Client connected', { userId: socket.userId });

    socket.on('message:read', async ({ messageId, conversationId }) => {
      // Notify sender that message was read
      const { pool } = require('../models/db');
      try {
        await pool.query(
          'UPDATE messages SET read_at = NOW() WHERE id = $1',
          [messageId]
        );
        // Could emit read receipt to sender here
      } catch (err) {
        logger.error('message:read error', { error: err.message });
      }
    });

    socket.on('disconnect', () => {
      logger.info('Client disconnected', { userId: socket.userId });
    });
  });

  return io;
}

function getIO() {
  if (!io) throw new Error('WebSocket not initialised');
  return io;
}

module.exports = { initWebSocket, getIO };
