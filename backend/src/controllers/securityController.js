const SecurityAlert = require('../models/SecurityAlert');
const AnomalyResult = require('../models/AnomalyResult');
const AuditLog = require('../models/AuditLog');
const AgentActivity = require('../models/AgentActivity');
const Agent = require('../models/Agent');
const auditService = require('../services/auditService');
const agentRuntime = require('../services/agentRuntime');
const ruleEngine = require('../services/ruleEngine');
const riskScoringService = require('../services/riskScoringService');
const mlClient = require('../services/mlClient');

exports.getAlerts = async (req, res, next) => {
  try {
    const { status, severity, agentId } = req.query;
    const query = {};
    if (status) query.status = status;
    if (severity) query.severity = severity;
    if (agentId) query.agentId = agentId;

    const alerts = await SecurityAlert.find(query).sort({ timestamp: -1 }).limit(100);
    res.json({ success: true, count: alerts.length, alerts });
  } catch (error) {
    next(error);
  }
};

exports.acknowledgeAlert = async (req, res, next) => {
  try {
    const { id } = req.params;
    const alert = await SecurityAlert.findOne({ alertId: id });
    if (!alert) {
      return res.status(404).json({ success: false, error: 'Alert not found' });
    }

    alert.status = 'acknowledged';
    alert.acknowledgedBy = req.user ? req.user.email : 'analyst';
    await alert.save();

    res.json({ success: true, message: 'Alert acknowledged', alert });
  } catch (error) {
    next(error);
  }
};

exports.resolveAlert = async (req, res, next) => {
  try {
    const { id } = req.params;
    const alert = await SecurityAlert.findOne({ alertId: id });
    if (!alert) {
      return res.status(404).json({ success: false, error: 'Alert not found' });
    }

    alert.status = 'resolved';
    alert.resolvedBy = req.user ? req.user.email : 'analyst';
    await alert.save();

    res.json({ success: true, message: 'Alert resolved', alert });
  } catch (error) {
    next(error);
  }
};

exports.getAnomalies = async (req, res, next) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 50, 100);
    const anomalies = await AnomalyResult.find().sort({ timestamp: -1 }).limit(limit);
    res.json({ success: true, count: anomalies.length, anomalies });
  } catch (error) {
    next(error);
  }
};

exports.getAuditLogs = async (req, res, next) => {
  try {
    const page = Math.max(0, Number(req.query.page) || 0);
    const limit = Math.min(Number(req.query.limit) || 50, 100);

    const total = await AuditLog.countDocuments();
    const logs = await AuditLog.find()
      .sort({ seq: -1 })
      .skip(page * limit)
      .limit(limit);

    res.json({
      success: true,
      total,
      page,
      pages: Math.ceil(total / limit),
      count: logs.length,
      logs
    });
  } catch (error) {
    next(error);
  }
};

exports.verifyAuditLogs = async (req, res, next) => {
  try {
    const result = await auditService.verifyChain();
    res.json({
      success: true,
      verification: result
    });
  } catch (error) {
    next(error);
  }
};

exports.getSecurityMetrics = async (req, res, next) => {
  try {
    const totalActivities = await AgentActivity.countDocuments();
    const allowed = await AgentActivity.countDocuments({ decision: 'ALLOW' });
    const blocked = await AgentActivity.countDocuments({ decision: 'DENY' });
    const pending = await AgentActivity.countDocuments({ decision: 'PENDING' });
    const activeAlerts = await SecurityAlert.countDocuments({ status: 'active' });
    const criticalAlerts = await SecurityAlert.countDocuments({ severity: 'critical', status: 'active' });
    const totalAgents = await Agent.countDocuments();
    const activeAgents = await Agent.countDocuments({ status: 'active' });

    const blockedRatio = totalActivities > 0 ? (blocked / totalActivities) : 0;
    const score = Math.max(0, Math.min(100, Math.round(
      100 - (blockedRatio * 30) - Math.min(30, criticalAlerts * 5) - Math.min(10, pending * 1.5)
    )));

    res.json({
      success: true,
      score,
      metrics: {
        totalRequests: totalActivities,
        authorizedCount: allowed,
        blockedCount: blocked,
        pendingApprovals: pending,
        totalAgents,
        activeAgents,
        activeAlerts,
        criticalAlerts,
        isGlobalFrozen: agentRuntime.isGlobalFrozen
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.analyzeActivity = async (req, res, next) => {
  try {
    const { agentId, action, resource, amount = 0, hour } = req.body;
    const agent = await Agent.findOne({ agentId });

    const recentActivities = await AgentActivity.find({
      agentId,
      timestamp: { $gte: new Date(Date.now() - 60000) }
    }).lean();

    const recentDenials = await AgentActivity.find({
      agentId,
      decision: 'DENY',
      timestamp: { $gte: new Date(Date.now() - 300000) }
    }).lean();

    const features = {
      api_request_frequency: recentActivities.length,
      denied_requests_count: recentDenials.length,
      failed_operations_count: recentDenials.length,
      sensitive_operations_ratio: recentActivities.filter(a => a.action === 'PAYMENT' || a.action === 'CUSTOMER_DATA').length / Math.max(1, recentActivities.length),
      permission_violations_count: recentDenials.length,
      unusual_access_time: (hour !== undefined ? (hour < 6 || hour >= 22) : (new Date().getHours() < 6 || new Date().getHours() >= 22)) ? 1 : 0,
      average_risk_score: agent ? agent.riskScore : 25,
      tool_calls_count: recentActivities.length + 1
    };

    const mlResult = await mlClient.predict(features);

    const ruleEval = ruleEngine.evaluate({
      agent,
      action,
      resource,
      amount,
      hour,
      recentRequestsIn60s: features.api_request_frequency,
      recentDenialsIn300s: features.denied_requests_count,
      isGlobalFrozen: agentRuntime.isGlobalFrozen
    });

    const risk = riskScoringService.calculateRisk({
      agentBaseline: agent ? agent.riskBase : 25,
      mlAnomalyScore: mlResult.anomalyScore,
      isAnomaly: mlResult.isAnomaly,
      ruleViolations: ruleEval.violations,
      action,
      recentDenialsCount: features.denied_requests_count,
      matchesSensitive: ruleEval.matchesSensitive
    });

    let decision = 'ALLOW';
    let reason = 'All security checks passed';
    if (ruleEval.hardDenyReason || risk.score >= 80) {
      decision = 'DENY';
      reason = ruleEval.hardDenyReason || `Composite risk score ${risk.score}/100 exceeds auto-block threshold.`;
    } else if (ruleEval.requiresHumanApproval || risk.score >= 55) {
      decision = 'PENDING';
      reason = ruleEval.requiresHumanApproval || `Elevated risk score ${risk.score}/100 requires human review.`;
    }

    res.json({
      success: true,
      decision,
      riskScore: risk.score,
      riskCategory: risk.category,
      reason,
      steps: ruleEval.steps,
      mlAnomaly: mlResult,
      breakdown: risk.breakdown
    });
  } catch (error) {
    next(error);
  }
};

exports.toggleFreeze = async (req, res, next) => {
  try {
    const { freeze } = req.body;
    const newState = freeze !== undefined ? Boolean(freeze) : !agentRuntime.isGlobalFrozen;
    agentRuntime.setGlobalFreeze(newState);

    await auditService.recordEvent({
      agentId: 'system',
      agentName: 'Control Plane',
      action: newState ? 'FREEZE_ALL' : 'RESUME_ALL',
      resource: 'control_plane://global_switch',
      decision: newState ? 'DENY' : 'ALLOW',
      riskScore: newState ? 100 : 0,
      reason: `Emergency global freeze toggled to ${newState} by ${req.user ? req.user.email : 'admin'}`
    });

    res.json({
      success: true,
      frozen: agentRuntime.isGlobalFrozen,
      message: agentRuntime.isGlobalFrozen ? 'Emergency freeze engaged: all agent executions blocked.' : 'All agents resumed.'
    });
  } catch (error) {
    next(error);
  }
};
