const mongoose = require('mongoose');

const AgentPermissionSchema = new mongoose.Schema({
  grantId: {
    type: String,
    required: true,
    unique: true
  },
  agentId: {
    type: String,
    required: true,
    index: true
  },
  permission: {
    type: String,
    required: true,
    enum: ['READ', 'WRITE', 'DELETE', 'UPDATE', 'API', 'CUSTOMER_DATA', 'PAYMENT']
  },
  action: {
    type: String,
    required: true,
    enum: ['GRANT', 'REVOKE']
  },
  grantedBy: {
    type: String,
    required: true
  },
  reason: {
    type: String,
    default: 'Administrative capability modification'
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('AgentPermission', AgentPermissionSchema);
