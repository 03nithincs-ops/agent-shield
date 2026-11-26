const mongoose = require('mongoose');

const AgentExecutionHistorySchema = new mongoose.Schema({
  executionId: {
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
  toolName: {
    type: String,
    required: true
  },
  parameters: {
    type: mongoose.Schema.Types.Mixed,
    default: () => ({})
  },
  output: {
    type: mongoose.Schema.Types.Mixed
  },
  success: {
    type: Boolean,
    required: true
  },
  errorMessage: {
    type: String
  },
  executionTimeMs: {
    type: Number,
    default: 0
  },
  approvedBy: {
    type: String
  },
  permissionChecked: {
    type: String,
    required: true
  },
  permissionGranted: {
    type: Boolean,
    required: true
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  }
});

module.exports = mongoose.model('AgentExecutionHistory', AgentExecutionHistorySchema);
