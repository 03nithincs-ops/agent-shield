const mongoose = require('mongoose');

const AnomalyResultSchema = new mongoose.Schema({
  anomalyId: {
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
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  isAnomaly: {
    type: Boolean,
    required: true
  },
  anomalyScore: {
    type: Number,
    required: true
  },
  prediction: {
    type: Number, // -1 for anomaly, 1 for normal
    required: true
  },
  features: {
    api_request_frequency: { type: Number, default: 0 },
    denied_requests_count: { type: Number, default: 0 },
    failed_operations_count: { type: Number, default: 0 },
    sensitive_operations_ratio: { type: Number, default: 0 },
    permission_violations_count: { type: Number, default: 0 },
    unusual_access_time: { type: Number, default: 0 },
    average_risk_score: { type: Number, default: 0 },
    tool_calls_count: { type: Number, default: 0 }
  },
  explanation: {
    type: String,
    default: ''
  },
  modelInfo: {
    modelType: { type: String, default: 'IsolationForest' },
    modelVersion: { type: String, default: '1.0.0' }
  }
});

module.exports = mongoose.model('AnomalyResult', AnomalyResultSchema);
