const Agent = require('../models/Agent');
const AgentActivity = require('../models/AgentActivity');
const AgentExecutionHistory = require('../models/AgentExecutionHistory');
const SecurityAlert = require('../models/SecurityAlert');
const { TOOLS } = require('./toolRegistry');
const ruleEngine = require('./ruleEngine');
const riskScoringService = require('./riskScoringService');
const mlClient = require('./mlClient');
const auditService = require('./auditService');

class AgentRuntime {
  constructor() {
    this.isGlobalFrozen = false;
    this.socketIO = null;
  }

  setSocketIO(io) {
    this.socketIO = io;
  }

  setGlobalFreeze(frozen) {
    this.isGlobalFrozen = frozen;
    if (this.socketIO) {
      this.socketIO.emit('control_plane:freeze', { frozen: this.isGlobalFrozen });
    }
  }

  /**
   * Execute an authorized task using a strictly registered tool
   */
  async executeTask(agentId, toolName, parameters = {}, actor = 'system') {
    const startTime = Date.now();
    const executionId = 'exec_' + Math.random().toString(36).slice(2, 9);

    // 1. Verify agent existence & approval status
    const agent = await Agent.findOne({ agentId });
    if (!agent) {
      throw new Error(`Agent with ID '${agentId}' does not exist.`);
    }

    if (this.isGlobalFrozen) {
      throw new Error('EXECUTION_BLOCKED: Control plane emergency freeze is engaged.');
    }

    if (agent.status !== 'approved' && agent.status !== 'running' && agent.status !== 'active') {
      throw new Error(`EXECUTION_BLOCKED: Agent status is '${agent.status}'. Execution requires human approval and activation.`);
    }

    // 2. Verify tool registration
    const tool = TOOLS[toolName];
    if (!tool) {
      throw new Error(`TOOL_NOT_FOUND: Tool '${toolName}' is not a registered runtime tool.`);
    }

    // 3. Verify tool is in agent's allowedTools blueprint
    if (!agent.allowedTools || !agent.allowedTools.includes(toolName)) {
      await this.recordViolation(agent, tool.requiredPermission, `tool://${toolName}`, 'Unregistered tool execution attempt', 65);
      throw new Error(`PERMISSION_DENIED: Tool '${toolName}' is not permitted in agent's allowedTools specification.`);
    }

    // 4. Verify agent has required permission for this tool
    const requiredPerm = tool.requiredPermission;
    const hasPermission = agent.permissions && agent.permissions[requiredPerm] === true;

    if (!hasPermission) {
      await this.recordViolation(agent, requiredPerm, `tool://${toolName}`, `Capability '${requiredPerm}' missing for tool '${toolName}'`, 70);
      throw new Error(`PERMISSION_DENIED: Agent lacks required '${requiredPerm}' permission to execute '${toolName}'.`);
    }

    // 5. Gather activity metrics for ML anomaly detection
    const recentActivities = await AgentActivity.find({
      agentId,
      timestamp: { $gte: new Date(Date.now() - 60000) }
    }).lean();

    const recentDenials = await AgentActivity.find({
      agentId,
      decision: 'DENY',
      timestamp: { $gte: new Date(Date.now() - 300000) }
    }).lean();

    // 6. Extract features for ML model
    const features = {
      api_request_frequency: recentActivities.length,
      denied_requests_count: recentDenials.length,
      failed_operations_count: recentDenials.length,
      sensitive_operations_ratio: recentActivities.filter(a => a.action === 'PAYMENT' || a.action === 'CUSTOMER_DATA').length / Math.max(1, recentActivities.length),
      permission_violations_count: recentDenials.length,
      unusual_access_time: (new Date().getHours() < 6 || new Date().getHours() >= 22) ? 1 : 0,
      average_risk_score: agent.riskScore || 20,
      tool_calls_count: recentActivities.length + 1
    };

    // 7. Isolation Forest ML Prediction
    const mlResult = await mlClient.predict(features);

    // 8. Deterministic Rule Engine Evaluation
    const ruleEvaluation = ruleEngine.evaluate({
      agent,
      action: requiredPerm,
      resource: `tool://${toolName}`,
      amount: parameters.amount || 0,
      recentRequestsIn60s: features.api_request_frequency,
      recentDenialsIn300s: features.denied_requests_count,
      isGlobalFrozen: this.isGlobalFrozen
    });

    // 9. Composite Risk Score
    const risk = riskScoringService.calculateRisk({
      agentBaseline: agent.riskBase || 15,
      mlAnomalyScore: mlResult.anomalyScore,
      isAnomaly: mlResult.isAnomaly,
      ruleViolations: ruleEvaluation.violations,
      action: requiredPerm,
      recentDenialsCount: features.denied_requests_count,
      matchesSensitive: ruleEvaluation.matchesSensitive
    });

    // 10. Check if risk triggers automatic quarantine
    if (risk.score >= 80) {
      agent.status = 'suspended';
      await agent.save();

      const alert = new SecurityAlert({
        alertId: 'alr_' + Math.random().toString(36).slice(2, 8),
        agentId: agent.agentId,
        agentName: agent.name,
        category: 'Excessive API Requests',
        title: `CRITICAL RISK QUARANTINE: ${agent.name}`,
        description: `Agent reached composite risk score ${risk.score}/100. Automatically quarantined by control plane.`,
        severity: 'critical',
        riskScore: risk.score,
        detectionSource: 'COMPOSITE',
        recommendedAction: 'Inspect agent activity and review permissions'
      });
      await alert.save();

      if (this.socketIO) {
        this.socketIO.emit('security:alert', alert);
        this.socketIO.emit('agent:status', { agentId: agent.agentId, status: agent.status });
      }

      throw new Error(`CRITICAL_RISK_QUARANTINE: Composite risk ${risk.score}/100 exceeded safety threshold (80). Agent suspended.`);
    }

    // 11. Execute registered tool with timeout enforcement
    const timeoutMs = agent.executionSettings?.maxExecutionTimeMs || 30000;
    let toolOutput;
    let executionSuccess = false;
    let executionError = null;

    try {
      toolOutput = await Promise.race([
        tool.execute(parameters, agent),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error(`Tool execution timed out after ${timeoutMs}ms`)), timeoutMs)
        )
      ]);
      executionSuccess = true;
    } catch (err) {
      executionError = err.message;
      throw err;
    } finally {
      const executionTimeMs = Date.now() - startTime;

      // 12. Record execution history
      const execHistory = new AgentExecutionHistory({
        executionId,
        agentId: agent.agentId,
        toolName,
        parameters,
        output: executionSuccess ? toolOutput : null,
        success: executionSuccess,
        errorMessage: executionError,
        executionTimeMs,
        approvedBy: actor,
        permissionChecked: requiredPerm,
        permissionGranted: hasPermission
      });
      await execHistory.save();

      // 13. Record activity log & emit real-time event
      const activityId = 'act_' + Math.random().toString(36).slice(2, 9);
      const activity = new AgentActivity({
        activityId,
        agentId: agent.agentId,
        agentName: agent.name,
        action: requiredPerm,
        resource: `tool://${toolName}`,
        parameters,
        decision: executionSuccess ? 'ALLOW' : 'DENY',
        riskScore: risk.score,
        reason: executionSuccess ? 'Tool executed successfully within permitted parameters' : `Failed: ${executionError}`,
        policyRule: ruleEvaluation.violations.length > 0 ? ruleEvaluation.violations[0].ruleId : 'P-01',
        anomalyDetected: mlResult.isAnomaly,
        anomalyScore: mlResult.anomalyScore,
        executionTimeMs
      });
      await activity.save();

      // 14. Append to tamper-evident SHA-256 audit chain
      await auditService.recordEvent({
        agentId: agent.agentId,
        agentName: agent.name,
        action: requiredPerm,
        resource: `tool://${toolName}`,
        decision: activity.decision,
        riskScore: risk.score,
        reason: activity.reason,
        metadata: { executionId, toolName }
      });

      // Update agent state
      agent.riskScore = risk.score;
      if (agent.status === 'approved') agent.status = 'running';
      await agent.save();

      // Broadcast Socket.IO real-time telemetry
      if (this.socketIO) {
        this.socketIO.emit('agent:activity', activity);
        this.socketIO.emit('agent:telemetry', {
          agentId: agent.agentId,
          riskScore: risk.score,
          status: agent.status
        });
      }
    }

    return {
      success: true,
      executionId,
      agentId: agent.agentId,
      toolName,
      output: toolOutput,
      risk: {
        score: risk.score,
        category: risk.category,
        explanation: risk.explanation
      },
      executionTimeMs: Date.now() - startTime
    };
  }

  async recordViolation(agent, action, resource, reason, score) {
    const activity = new AgentActivity({
      activityId: 'act_' + Math.random().toString(36).slice(2, 9),
      agentId: agent.agentId,
      agentName: agent.name,
      action,
      resource,
      decision: 'DENY',
      riskScore: score,
      reason,
      policyRule: 'P-01'
    });
    await activity.save();

    await auditService.recordEvent({
      agentId: agent.agentId,
      agentName: agent.name,
      action,
      resource,
      decision: 'DENY',
      riskScore: score,
      reason
    });

    if (this.socketIO) {
      this.socketIO.emit('agent:activity', activity);
    }
  }
}

module.exports = new AgentRuntime();
