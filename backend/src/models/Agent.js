const mongoose = require('mongoose');

const AgentSchema = new mongoose.Schema({
  agentId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    default: ''
  },
  objective: {
    type: String,
    default: ''
  },
  instructions: {
    type: String,
    default: ''
  },
  model: {
    type: String,
    default: 'qwen3'
  },
  status: {
    type: String,
    enum: ['draft', 'pending_approval', 'approved', 'running', 'active', 'stopped', 'suspended', 'disabled', 'failed', 'revoked'],
    default: 'draft',
    index: true
  },
  riskLevel: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    default: 'LOW'
  },
  riskScore: {
    type: Number,
    default: 15,
    min: 0,
    max: 100
  },
  riskBase: {
    type: Number,
    default: 15
  },
  seed: {
    type: Number,
    default: () => Math.floor(Math.random() * 1000000)
  },
  allowedTools: [{
    type: String
  }],
  permissions: {
    READ: { type: Boolean, default: true },
    WRITE: { type: Boolean, default: false },
    DELETE: { type: Boolean, default: false },
    UPDATE: { type: Boolean, default: false },
    API: { type: Boolean, default: false },
    CUSTOMER_DATA: { type: Boolean, default: false },
    PAYMENT: { type: Boolean, default: false }
  },
  safetyRestrictions: [{
    type: String
  }],
  executionSettings: {
    maxExecutionTimeMs: { type: Number, default: 30000 },
    maxRequestsPerMin: { type: Number, default: 15 },
    requireHumanApprovalForSensitive: { type: Boolean, default: true }
  },
  approvalHistory: [{
    action: { type: String, enum: ['REQUESTED', 'APPROVED', 'REJECTED', 'SUSPENDED', 'RESUMED', 'RECOVERED', 'REVOKED'] },
    decidedBy: { type: String },
    timestamp: { type: Date, default: Date.now },
    notes: { type: String }
  }],
  recoveryHistory: [{
    authorizedBy: { type: String, required: true },
    reason: { type: String, required: true },
    mitigationNotes: { type: String, default: '' },
    previousRiskScore: { type: Number },
    reassessedRiskScore: { type: Number },
    timestamp: { type: Date, default: Date.now }
  }],
  createdBy: {
    type: String,
    default: 'system'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

AgentSchema.pre('save', function (next) {
  this.updatedAt = new Date();
  next();
});

module.exports = mongoose.model('Agent', AgentSchema);
