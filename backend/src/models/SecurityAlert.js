const mongoose = require('mongoose');

const SecurityAlertSchema = new mongoose.Schema({
  alertId: {
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
  category: {
    type: String,
    required: true,
    enum: [
      'Excessive API Requests',
      'Repeated Unauthorized Access',
      'Unusual Access Time',
      'Suspicious Resource Access',
      'Unexpected Agent Behaviour',
      'Permission Violation',
      'Sensitive Action Threshold',
      'ML Isolation Forest Anomaly'
    ]
  },
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium',
    index: true
  },
  riskScore: {
    type: Number,
    required: true
  },
  detectionSource: {
    type: String,
    enum: ['RULE_ENGINE', 'ISOLATION_FOREST', 'PERMISSION_GATEWAY', 'COMPOSITE'],
    default: 'RULE_ENGINE'
  },
  recommendedAction: {
    type: String,
    default: 'Review agent activity and consider quarantine'
  },
  status: {
    type: String,
    enum: ['active', 'acknowledged', 'resolved', 'dismissed'],
    default: 'active',
    index: true
  },
  acknowledgedBy: {
    type: String
  },
  resolvedBy: {
    type: String
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  }
});

module.exports = mongoose.model('SecurityAlert', SecurityAlertSchema);
