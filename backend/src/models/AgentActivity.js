const mongoose = require('mongoose');

const AgentActivitySchema = new mongoose.Schema({
  activityId: {
    type: String,
    required: true,
    unique: true,
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
  parameters: {
    type: mongoose.Schema.Types.Mixed,
    default: () => ({})
  },
  decision: {
    type: String,
    enum: ['ALLOW', 'DENY', 'PENDING'],
    required: true,
    index: true
  },
  riskScore: {
    type: Number,
    required: true,
    min: 0,
    max: 100
  },
  reason: {
    type: String,
    default: ''
  },
  policyRule: {
    type: String
  },
  anomalyDetected: {
    type: Boolean,
    default: false
  },
  anomalyScore: {
    type: Number,
    default: 0
  },
  executionTimeMs: {
    type: Number,
    default: 0
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  }
});

module.exports = mongoose.model('AgentActivity', AgentActivitySchema);
