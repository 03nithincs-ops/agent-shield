const AgentActivity = require('../models/AgentActivity');
const SecurityAlert = require('../models/SecurityAlert');
const Agent = require('../models/Agent');
const ruleEngine = require('../services/ruleEngine');
const riskScoringService = require('../services/riskScoringService');
const mlClient = require('../services/mlClient');
const auditService = require('../services/auditService');
const agentRuntime = require('../services/agentRuntime');

exports.getMetrics = async (req, res, next) => {
  try {
    const total = await AgentActivity.countDocuments();
    const allowed = await AgentActivity.countDocuments({ decision: 'ALLOW' });
    const blocked = await AgentActivity.countDocuments({ decision: 'DENY' });
    const pending = await AgentActivity.countDocuments({ decision: 'PENDING' });
    const totalAgents = await Agent.countDocuments();
    const activeAgents = await Agent.countDocuments({ status: 'active' });
    const criticalAlerts = await SecurityAlert.countDocuments({ severity: 'critical', status: 'active' });

    const blockedRatio = total > 0 ? (blocked / total) : 0;
    const score = Math.max(0, Math.min(100, Math.round(
      100 - (blockedRatio * 30) - (criticalAlerts * 5)
    )));

    res.json({
      success: true,
      score,
      totalRequests: total,
      authorizedCount: allowed,
      blockedCount: blocked,
      pendingCount: pending,
      totalAgents,
      activeAgents,
      criticalAlerts,
      isGlobalFrozen: agentRuntime.isGlobalFrozen
    });
  } catch (error) {
    next(error);
  }
};

exports.getActivity = async (req, res, next) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 30, 100);
    const activities = await AgentActivity.find()
      .sort({ timestamp: -1 })
      .limit(limit);

    res.json({
      success: true,
      count: activities.length,
      activities
    });
  } catch (error) {
    next(error);
  }
};

exports.simulate = async (req, res, next) => {
  try {
    const { agentId, action, resource, amount = 0, hour, commit = false } = req.body;
    const agent = await Agent.findOne({ agentId });

    if (!agent) {
      return res.status(404).json({ success: false, error: 'Agent not found' });
    }

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
      api_request_frequency: recentActivities.length + 1,
      denied_requests_count: recentDenials.length,
      failed_operations_count: recentDenials.length,
      sensitive_operations_ratio: recentActivities.filter(a => a.action === 'PAYMENT' || a.action === 'CUSTOMER_DATA').length / Math.max(1, recentActivities.length),
      permission_violations_count: recentDenials.length,
      unusual_access_time: (hour !== undefined ? (hour < 6 || hour >= 22) : (new Date().getHours() < 6 || new Date().getHours() >= 22)) ? 1 : 0,
      average_risk_score: agent.riskScore || 20,
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
      agentBaseline: agent.riskBase || 15,
      mlAnomalyScore: mlResult.anomalyScore,
      isAnomaly: mlResult.isAnomaly,
      ruleViolations: ruleEval.violations,
      action,
      recentDenialsCount: features.denied_requests_count,
      matchesSensitive: ruleEval.matchesSensitive
    });

    let decision = 'ALLOW';
    let reason = 'All policy checks passed';

    if (ruleEval.hardDenyReason || risk.score >= 80) {
      decision = 'DENY';
      reason = ruleEval.hardDenyReason || `Composite risk score ${risk.score}/100 exceeds auto-block threshold.`;
    } else if (ruleEval.requiresHumanApproval || risk.score >= 55) {
      decision = 'PENDING';
      reason = ruleEval.requiresHumanApproval || `Elevated risk score ${risk.score}/100 requires human review.`;
    }

    let recordedActivity = null;
    if (commit) {
      const activityId = 'act_' + Math.random().toString(36).slice(2, 9);
      recordedActivity = new AgentActivity({
        activityId,
        agentId: agent.agentId,
        agentName: agent.name,
        action,
        resource,
        parameters: { amount },
        decision,
        riskScore: risk.score,
        reason,
        policyRule: ruleEval.violations.length > 0 ? ruleEval.violations[0].ruleId : 'P-01',
        anomalyDetected: mlResult.isAnomaly,
        anomalyScore: mlResult.anomalyScore
      });
      await recordedActivity.save();

      await auditService.recordEvent({
        agentId: agent.agentId,
        agentName: agent.name,
        action,
        resource,
        decision,
        riskScore: risk.score,
        reason
      });

      // If pending and payment, create alert or approval item
      if (decision === 'PENDING') {
        const alert = new SecurityAlert({
          alertId: 'alr_' + Math.random().toString(36).slice(2, 8),
          agentId: agent.agentId,
          agentName: agent.name,
          category: action === 'PAYMENT' ? 'Sensitive Action Threshold' : 'Permission Violation',
          title: `Action Held for Human Approval: ${agent.name}`,
          description: reason,
          severity: risk.score >= 75 ? 'critical' : 'high',
          riskScore: risk.score,
          detectionSource: 'RULE_ENGINE',
          recommendedAction: 'Review and approve/reject in Approvals console'
        });
        await alert.save();
        if (agentRuntime.socketIO) agentRuntime.socketIO.emit('security:alert', alert);
      }

      agent.riskScore = risk.score;
      await agent.save();

      if (agentRuntime.socketIO) {
        agentRuntime.socketIO.emit('agent:activity', recordedActivity);
        agentRuntime.socketIO.emit('agent:telemetry', {
          agentId: agent.agentId,
          riskScore: risk.score,
          status: agent.status
        });
      }
    }

    res.json({
      success: true,
      decision,
      riskScore: risk.score,
      riskCategory: risk.category,
      reason,
      steps: ruleEval.steps,
      mlAnomaly: mlResult,
      breakdown: risk.breakdown,
      committed: commit,
      activity: recordedActivity
    });
  } catch (error) {
    next(error);
  }
};
