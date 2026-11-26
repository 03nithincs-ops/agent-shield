const mongoose = require('mongoose');

const AuditLogSchema = new mongoose.Schema({
  seq: {
    type: Number,
    required: true,
    unique: true,
    index: true
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  agentId: {
    type: String,
    required: true,
    index: true
  },
  agentName: {
    type: String,
    required: true
  },
  action: {
    type: String,
    required: true
  },
  resource: {
    type: String,
    required: true
  },
  decision: {
    type: String,
    enum: ['ALLOW', 'DENY', 'PENDING'],
    required: true
  },
  riskScore: {
    type: Number,
    required: true
  },
  reason: {
    type: String,
    required: true
  },
  prevHash: {
    type: String,
    required: true
  },
  hash: {
    type: String,
    required: true,
    unique: true
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: () => ({})
  }
});

module.exports = mongoose.model('AuditLog', AuditLogSchema);
