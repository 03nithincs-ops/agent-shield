const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config/env');

function setupSockets(io) {
  // Optional auth middleware for sockets
  io.use((socket, next) => {
    const token = socket.handshake.auth?.token || socket.handshake.query?.token;
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.user = decoded;
      } catch (err) {
        console.warn('[Socket.IO] Unverified socket connected.');
      }
    }
    next();
  });

  io.on('connection', (socket) => {
    console.log(`[Socket.IO] Client connected: ${socket.id} (User: ${socket.user?.email || 'guest'})`);

    socket.on('subscribe:agent', (agentId) => {
      socket.join(`agent:${agentId}`);
    });

    socket.on('unsubscribe:agent', (agentId) => {
      socket.leave(`agent:${agentId}`);
    });

    socket.on('disconnect', () => {
      console.log(`[Socket.IO] Client disconnected: ${socket.id}`);
    });
  });

  return io;
}

module.exports = setupSockets;
