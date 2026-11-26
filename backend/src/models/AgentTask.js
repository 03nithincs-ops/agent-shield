const mongoose = require('mongoose');

const AgentTaskSchema = new mongoose.Schema({
  taskId: {
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
  taskName: {
    type: String,
    required: true
  },
  description: {
    type: String,
    default: ''
  },
  status: {
    type: String,
    enum: ['pending', 'in_progress', 'completed', 'failed', 'blocked'],
    default: 'pending'
  },
  parameters: {
    type: mongoose.Schema.Types.Mixed,
    default: () => ({})
  },
  result: {
    type: mongoose.Schema.Types.Mixed
  },
  executedAt: {
    type: Date
  },
  completedAt: {
    type: Date
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('AgentTask', AgentTaskSchema);
