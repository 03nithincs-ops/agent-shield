const Agent = require('../models/Agent');
const AgentActivity = require('../models/AgentActivity');
const AgentExecutionHistory = require('../models/AgentExecutionHistory');
const AgentPermission = require('../models/AgentPermission');
const agentRuntime = require('../services/agentRuntime');
const auditService = require('../services/auditService');

exports.getAgents = async (req, res, next) => {
  try {
    const agents = await Agent.find().sort({ createdAt: -1 });
    res.json({
      success: true,
      count: agents.length,
      agents
    });
  } catch (error) {
    next(error);
  }
};

exports.getAgentById = async (req, res, next) => {
  try {
    const { id } = req.params;
    const agent = await Agent.findOne({ $or: [{ agentId: id }, { _id: id.match(/^[0-9a-fA-F]{24}$/) ? id : null }] });
    if (!agent) {
      return res.status(404).json({ success: false, error: 'Agent not found' });
    }
    res.json({ success: true, agent });
  } catch (error) {
    next(error);
  }
};

exports.createAgent = async (req, res, next) => {
  try {
    const data = req.body;
    const agentId = 'agt_' + Math.random().toString(36).slice(2, 6);
    
    // Explicit human approval required before activation
    const agent = new Agent({
      agentId,
      name: data.name,
      description: data.description || '',
      objective: data.objective || '',
      instructions: data.instructions || '',
      model: data.model || 'qwen3',
      status: 'pending_approval',
      riskBase: data.riskBase || 15,
      riskScore: data.riskBase || 15,
      allowedTools: data.allowedTools || ['read_security_logs'],
      permissions: data.permissions || { READ: true },
      safetyRestrictions: data.safetyRestrictions || [],
      executionSettings: data.executionSettings || {},
      createdBy: req.user ? req.user.email : 'system'
    });

    await agent.save();

    // Record initial permission grants
    for (const [perm, granted] of Object.entries(agent.permissions)) {
      if (granted) {
        await new AgentPermission({
          grantId: 'g_' + Math.random().toString(36).slice(2, 8),
          agentId: agent.agentId,
          permission: perm,
          action: 'GRANT',
          grantedBy: req.user ? req.user.email : 'system',
          reason: 'Initial agent configuration grant'
        }).save();
      }
    }

    await auditService.recordEvent({
      agentId: agent.agentId,
      agentName: agent.name,
      action: 'CREATE_AGENT',
      resource: `agent://${agent.agentId}`,
      decision: 'PENDING',
      riskScore: agent.riskScore,
      reason: 'Agent created in pending_approval state awaiting human review'
    });

    res.status(201).json({
      success: true,
      message: 'Agent created successfully and placed in pending_approval state.',
      agent
    });
  } catch (error) {
    next(error);
  }
};

exports.updateAgent = async (req, res, next) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    const agent = await Agent.findOne({ $or: [{ agentId: id }, { _id: id.match(/^[0-9a-fA-F]{24}$/) ? id : null }] });
    if (!agent) {
      return res.status(404).json({ success: false, error: 'Agent not found' });
    }

    // Track permission modifications
    if (updates.permissions) {
      for (const [perm, newVal] of Object.entries(updates.permissions)) {
        const oldVal = agent.permissions[perm];
        if (oldVal !== newVal) {
          await new AgentPermission({
            grantId: 'g_' + Math.random().toString(36).slice(2, 8),
            agentId: agent.agentId,
            permission: perm,
            action: newVal ? 'GRANT' : 'REVOKE',
            grantedBy: req.user ? req.user.email : 'system',
            reason: `Administrative capability change: ${perm} set to ${newVal}`
          }).save();
        }
      }
    }

    Object.assign(agent, updates);
    await agent.save();

    res.json({
      success: true,
      message: 'Agent updated successfully',
      agent
    });
  } catch (error) {
    next(error);
  }
};

exports.deleteAgent = async (req, res, next) => {
  try {
    const { id } = req.params;
    const agent = await Agent.findOneAndDelete({ $or: [{ agentId: id }, { _id: id.match(/^[0-9a-fA-F]{24}$/) ? id : null }] });
    if (!agent) {
      return res.status(404).json({ success: false, error: 'Agent not found' });
    }

    await auditService.recordEvent({
      agentId: agent.agentId,
      agentName: agent.name,
      action: 'DELETE_AGENT',
      resource: `agent://${agent.agentId}`,
      decision: 'ALLOW',
      riskScore: 20,
      reason: `Agent deleted by administrator ${req.user ? req.user.email : 'system'}`
    });

    res.json({ success: true, message: `Agent '${agent.name}' deleted successfully.` });
  } catch (error) {
    next(error);
  }
};

exports.approveAgent = async (req, res, next) => {
  try {
    const { id } = req.params;
    const agent = await Agent.findOne({ $or: [{ agentId: id }, { _id: id.match(/^[0-9a-fA-F]{24}$/) ? id : null }] });
    if (!agent) {
      return res.status(404).json({ success: false, error: 'Agent not found' });
    }

    if (agent.status === 'revoked') {
      return res.status(400).json({ success: false, error: "Cannot approve agent in 'revoked' state. Agent is permanently decommissioned." });
    }
    if (agent.status === 'suspended') {
      return res.status(400).json({ success: false, error: "Cannot directly approve a 'suspended' agent. Use the dedicated administrator recovery endpoint (/recover)." });
    }

    agent.status = 'approved';
    agent.approvalHistory.push({
      action: 'APPROVED',
      decidedBy: req.user ? req.user.email : 'admin',
      notes: req.body.notes || 'Human authorization granted'
    });
    await agent.save();

    await auditService.recordEvent({
      agentId: agent.agentId,
      agentName: agent.name,
      action: 'APPROVE_AGENT',
      resource: `agent://${agent.agentId}`,
      decision: 'ALLOW',
      riskScore: agent.riskScore,
      reason: `Agent approved by ${req.user ? req.user.email : 'admin'}`
    });

    if (agentRuntime.socketIO) {
      agentRuntime.socketIO.emit('agent:status', { agentId: agent.agentId, status: agent.status });
    }

    res.json({ success: true, message: `Agent '${agent.name}' approved for execution.`, agent });
  } catch (error) {
    next(error);
  }
};

exports.rejectAgent = async (req, res, next) => {
  try {
    const { id } = req.params;
    const agent = await Agent.findOne({ $or: [{ agentId: id }, { _id: id.match(/^[0-9a-fA-F]{24}$/) ? id : null }] });
    if (!agent) {
      return res.status(404).json({ success: false, error: 'Agent not found' });
    }

    agent.status = 'disabled';
    agent.approvalHistory.push({
      action: 'REJECTED',
      decidedBy: req.user ? req.user.email : 'admin',
      notes: req.body.notes || 'Agent rejected during review'
    });
    await agent.save();

    res.json({ success: true, message: `Agent '${agent.name}' rejected.`, agent });
  } catch (error) {
    next(error);
  }
};

exports.startAgent = async (req, res, next) => {
  try {
    const { id } = req.params;
    const agent = await Agent.findOne({ $or: [{ agentId: id }, { _id: id.match(/^[0-9a-fA-F]{24}$/) ? id : null }] });
    if (!agent) {
      return res.status(404).json({ success: false, error: 'Agent not found' });
    }

    if (agent.status === 'suspended') {
      return res.status(400).json({
        success: false,
        error: "Cannot start agent in 'suspended' state. Agent must undergo administrator-authorized recovery before activation."
      });
    }

    if (agent.status === 'revoked') {
      return res.status(400).json({
        success: false,
        error: "Cannot start agent in 'revoked' state. Agent is permanently decommissioned."
      });
    }

    if (agent.status !== 'approved' && agent.status !== 'stopped') {
      return res.status(400).json({
        success: false,
        error: `Cannot start agent in '${agent.status}' state. Agent must be 'approved' or 'stopped'.`
      });
    }

    agent.status = 'active';
    await agent.save();

    await auditService.recordEvent({
      agentId: agent.agentId,
      agentName: agent.name,
      action: 'START_AGENT',
      resource: `agent://${agent.agentId}`,
      decision: 'ALLOW',
      riskScore: agent.riskScore,
      reason: `Agent activated by ${req.user ? req.user.email : 'system'}`
    });

    if (agentRuntime.socketIO) {
      agentRuntime.socketIO.emit('agent:status', { agentId: agent.agentId, status: agent.status });
      agentRuntime.socketIO.emit('agent:telemetry', { agentId: agent.agentId, riskScore: agent.riskScore, status: agent.status });
    }

    res.json({ success: true, message: `Agent '${agent.name}' started and active.`, agent });
  } catch (error) {
    next(error);
  }
};

exports.stopAgent = async (req, res, next) => {
  try {
    const { id } = req.params;
    const agent = await Agent.findOne({ $or: [{ agentId: id }, { _id: id.match(/^[0-9a-fA-F]{24}$/) ? id : null }] });
    if (!agent) {
      return res.status(404).json({ success: false, error: 'Agent not found' });
    }

    if (agent.status === 'revoked') {
      return res.status(400).json({ success: false, error: "Cannot stop agent in 'revoked' state." });
    }

    agent.status = 'stopped';
    await agent.save();

    await auditService.recordEvent({
      agentId: agent.agentId,
      agentName: agent.name,
      action: 'STOP_AGENT',
      resource: `agent://${agent.agentId}`,
      decision: 'ALLOW',
      riskScore: agent.riskScore,
      reason: `Agent stopped by ${req.user ? req.user.email : 'system'}`
    });

    if (agentRuntime.socketIO) {
      agentRuntime.socketIO.emit('agent:status', { agentId: agent.agentId, status: agent.status });
    }

    res.json({ success: true, message: `Agent '${agent.name}' stopped.`, agent });
  } catch (error) {
    next(error);
  }
};

exports.suspendAgent = async (req, res, next) => {
  try {
    const { id } = req.params;
    const agent = await Agent.findOne({ $or: [{ agentId: id }, { _id: id.match(/^[0-9a-fA-F]{24}$/) ? id : null }] });
    if (!agent) {
      return res.status(404).json({ success: false, error: 'Agent not found' });
    }

    if (agent.status === 'revoked') {
      return res.status(400).json({ success: false, error: "Cannot suspend a 'revoked' agent." });
    }

    agent.status = 'suspended';
    agent.approvalHistory.push({
      action: 'SUSPENDED',
      decidedBy: req.user ? req.user.email : 'security_analyst',
      notes: req.body.reason || 'Quarantined due to security violation'
    });
    await agent.save();

    await auditService.recordEvent({
      agentId: agent.agentId,
      agentName: agent.name,
      action: 'SUSPEND_AGENT',
      resource: `agent://${agent.agentId}`,
      decision: 'DENY',
      riskScore: Math.max(agent.riskScore || 0, 85),
      reason: req.body.reason || 'Agent quarantined by security control plane'
    });

    if (agentRuntime.socketIO) {
      agentRuntime.socketIO.emit('agent:status', { agentId: agent.agentId, status: agent.status });
      agentRuntime.socketIO.emit('agent:telemetry', { agentId: agent.agentId, riskScore: agent.riskScore, status: agent.status });
    }

    res.json({ success: true, message: `Agent '${agent.name}' suspended and quarantined.`, agent });
  } catch (error) {
    next(error);
  }
};

const PERMISSION_WEIGHTS = {
  READ: 4,
  WRITE: 10,
  UPDATE: 8,
  DELETE: 20,
  API: 8,
  CUSTOMER_DATA: 16,
  PAYMENT: 24
};

exports.recoverAgent = async (req, res, next) => {
  try {
    const { id } = req.params;
    const agent = await Agent.findOne({ $or: [{ agentId: id }, { _id: id.match(/^[0-9a-fA-F]{24}$/) ? id : null }] });
    if (!agent) {
      return res.status(404).json({ success: false, error: 'Agent not found' });
    }

    // Role check: Only ADMIN can authorize recovery
    if (!req.user || req.user.role !== 'ADMIN') {
      return res.status(403).json({
        success: false,
        error: 'Administrator authorization required. Only users with role ADMIN can recover suspended agents.'
      });
    }

    // State check: Permanent terminal state check
    if (agent.status === 'revoked') {
      return res.status(400).json({
        success: false,
        error: 'Revoked agents are permanently decommissioned and cannot be recovered.'
      });
    }

    // State check: Only suspended agents can enter recovery workflow
    if (agent.status !== 'suspended') {
      return res.status(400).json({
        success: false,
        error: `Only suspended agents can enter the recovery workflow. Current state is '${agent.status}'.`
      });
    }

    // Input validation: Meaningful justification and mitigation notes
    const justification = (req.body.justification || req.body.reason || '').trim();
    const mitigationNotes = (req.body.mitigationNotes || req.body.notes || '').trim();

    if (!justification || justification.length < 10) {
      return res.status(400).json({
        success: false,
        error: 'A meaningful recovery justification is required (minimum 10 characters explaining root-cause mitigation).'
      });
    }

    // Preserve historical data: Do not wipe alerts, execution history, or activity logs.
    const previousRiskScore = agent.riskScore || 85;

    // Risk Reassessment & Permission Review:
    // Review existing permissions without automatically granting any new capabilities
    const grantedPerms = Object.entries(agent.permissions || {})
      .filter(([_, granted]) => granted === true)
      .map(([perm]) => perm);

    const maxPermWeight = grantedPerms.reduce((max, p) => Math.max(max, PERMISSION_WEIGHTS[p] || 4), 4);
    const baseline = agent.riskBase || 15;

    // Structured formula: reassess post-mitigation baseline while keeping score safe (< 70)
    const reassessedRiskScore = Math.min(65, Math.max(baseline, Math.round(baseline * 0.5 + maxPermWeight * 1.5)));

    agent.riskScore = reassessedRiskScore;
    agent.riskLevel = reassessedRiskScore >= 70 ? 'HIGH' : reassessedRiskScore >= 40 ? 'MEDIUM' : 'LOW';

    // Transition suspended -> approved (NEVER directly to active)
    agent.status = 'approved';

    const recoveryEntry = {
      authorizedBy: req.user.email,
      reason: justification,
      mitigationNotes: mitigationNotes || 'Permissions and security parameters reviewed and confirmed safe for deployment.',
      previousRiskScore,
      reassessedRiskScore,
      timestamp: new Date()
    };

    agent.recoveryHistory.push(recoveryEntry);
    agent.approvalHistory.push({
      action: 'RECOVERED',
      decidedBy: req.user.email,
      notes: `Administrator recovery authorized: ${justification}. Risk reassessed to ${reassessedRiskScore}/100. Status set to approved.`
    });

    await agent.save();

    // Record recovery authorization and result in SHA-256 audit chain
    await auditService.recordEvent({
      agentId: agent.agentId,
      agentName: agent.name,
      action: 'RECOVER_AGENT',
      resource: `agent://${agent.agentId}`,
      decision: 'ALLOW',
      riskScore: reassessedRiskScore,
      reason: `Administrator authorized recovery: ${justification}`,
      metadata: {
        authorizedBy: req.user.email,
        previousStatus: 'suspended',
        newStatus: 'approved',
        previousRiskScore,
        reassessedRiskScore,
        mitigationNotes: recoveryEntry.mitigationNotes,
        retainedPermissions: grantedPerms
      }
    });

    // Real-time broadcast
    if (agentRuntime.socketIO) {
      agentRuntime.socketIO.emit('agent:status', { agentId: agent.agentId, status: agent.status });
      agentRuntime.socketIO.emit('agent:telemetry', { agentId: agent.agentId, riskScore: agent.riskScore, status: agent.status });
    }

    res.json({
      success: true,
      message: `Agent '${agent.name}' successfully recovered by administrator and restored to 'approved' state. Human-in-the-loop activation (/start) required to activate.`,
      agent,
      recovery: {
        authorizedBy: req.user.email,
        status: agent.status,
        previousRiskScore,
        reassessedRiskScore,
        justification
      },
      reassessment: {
        previousRiskScore,
        reassessedRiskScore,
        status: agent.status
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.revokeAgent = async (req, res, next) => {
  try {
    const { id } = req.params;
    const agent = await Agent.findOne({ $or: [{ agentId: id }, { _id: id.match(/^[0-9a-fA-F]{24}$/) ? id : null }] });
    if (!agent) {
      return res.status(404).json({ success: false, error: 'Agent not found' });
    }

    if (!req.user || req.user.role !== 'ADMIN') {
      return res.status(403).json({
        success: false,
        error: 'Administrator authorization required to revoke agents.'
      });
    }

    if (agent.status === 'revoked') {
      return res.status(400).json({
        success: false,
        error: 'Agent is already revoked and permanently decommissioned.'
      });
    }

    const previousStatus = agent.status;
    agent.status = 'revoked';
    const reason = req.body.reason || 'Agent permanently decommissioned by administrator';

    agent.approvalHistory.push({
      action: 'REVOKED',
      decidedBy: req.user.email,
      notes: reason
    });

    await agent.save();

    await auditService.recordEvent({
      agentId: agent.agentId,
      agentName: agent.name,
      action: 'REVOKE_AGENT',
      resource: `agent://${agent.agentId}`,
      decision: 'DENY',
      riskScore: agent.riskScore,
      reason: `Agent revoked: ${reason}`,
      metadata: {
        authorizedBy: req.user.email,
        previousStatus,
        newStatus: 'revoked'
      }
    });

    if (agentRuntime.socketIO) {
      agentRuntime.socketIO.emit('agent:status', { agentId: agent.agentId, status: agent.status });
    }

    res.json({
      success: true,
      message: `Agent '${agent.name}' permanently revoked and decommissioned.`,
      agent
    });
  } catch (error) {
    next(error);
  }
};

exports.executeTask = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { toolName, parameters } = req.body;

    const result = await agentRuntime.executeTask(
      id,
      toolName,
      parameters || {},
      req.user ? req.user.email : 'api_client'
    );

    res.json({
      success: true,
      message: 'Task executed successfully in controlled runtime',
      result
    });
  } catch (error) {
    res.status(403).json({
      success: false,
      error: error.message
    });
  }
};

exports.getActivity = async (req, res, next) => {
  try {
    const { id } = req.params;
    const limit = Math.min(Number(req.query.limit) || 50, 100);
    const activities = await AgentActivity.find({ agentId: id })
      .sort({ timestamp: -1 })
      .limit(limit);

    res.json({ success: true, count: activities.length, activities });
  } catch (error) {
    next(error);
  }
};

exports.getHistory = async (req, res, next) => {
  try {
    const { id } = req.params;
    const limit = Math.min(Number(req.query.limit) || 50, 100);
    const history = await AgentExecutionHistory.find({ agentId: id })
      .sort({ timestamp: -1 })
      .limit(limit);

    res.json({ success: true, count: history.length, history });
  } catch (error) {
    next(error);
  }
};
