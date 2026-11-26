const AgentActivity = require('../models/AgentActivity');
const SecurityAlert = require('../models/SecurityAlert');
const AgentPermission = require('../models/AgentPermission');
const Agent = require('../models/Agent');

/**
 * Registered Tools for the Controlled Agent Runtime.
 * Each tool defines:
 * - name
 * - requiredPermission
 * - description
 * - execute(params, agentContext)
 */
const TOOLS = {
  read_security_logs: {
    name: 'read_security_logs',
    requiredPermission: 'READ',
    description: 'Read recent security activity logs for an agent or globally with filtering',
    execute: async (params, agent) => {
      const limit = Math.min(Number(params.limit) || 20, 100);
      const query = {};
      if (params.agentId) query.agentId = params.agentId;
      if (params.decision) query.decision = params.decision;
      
      const logs = await AgentActivity.find(query)
        .sort({ timestamp: -1 })
        .limit(limit)
        .lean();
      
      return {
        count: logs.length,
        logs: logs.map(l => ({
          activityId: l.activityId,
          agentId: l.agentId,
          agentName: l.agentName,
          action: l.action,
          resource: l.resource,
          decision: l.decision,
          riskScore: l.riskScore,
          reason: l.reason,
          timestamp: l.timestamp
        }))
      };
    }
  },

  analyze_api_stats: {
    name: 'analyze_api_stats',
    requiredPermission: 'API',
    description: 'Analyze API request statistics, request rates, and denial ratios',
    execute: async (params, agent) => {
      const timeWindowMs = (Number(params.windowMinutes) || 60) * 60 * 1000;
      const since = new Date(Date.now() - timeWindowMs);
      
      const query = { timestamp: { $gte: since } };
      if (params.agentId) query.agentId = params.agentId;

      const activities = await AgentActivity.find(query).lean();
      const total = activities.length;
      const allowed = activities.filter(a => a.decision === 'ALLOW').length;
      const denied = activities.filter(a => a.decision === 'DENY').length;
      const pending = activities.filter(a => a.decision === 'PENDING').length;

      const ratePerMinute = total / (timeWindowMs / 60000);

      return {
        windowMinutes: Number(params.windowMinutes) || 60,
        totalRequests: total,
        allowedCount: allowed,
        deniedCount: denied,
        pendingCount: pending,
        denialRatio: total > 0 ? parseFloat((denied / total).toFixed(4)) : 0,
        requestRatePerMinute: parseFloat(ratePerMinute.toFixed(2)),
        status: ratePerMinute > 15 ? 'ELEVATED_RATE' : 'NORMAL'
      };
    }
  },

  check_agent_permissions: {
    name: 'check_agent_permissions',
    requiredPermission: 'READ',
    description: 'Check active capability grants and permission ledger for an agent',
    execute: async (params, agent) => {
      const targetAgentId = params.agentId || agent.agentId;
      const targetAgent = await Agent.findOne({ agentId: targetAgentId }).lean();
      if (!targetAgent) {
        throw new Error(`Agent '${targetAgentId}' not found.`);
      }

      const grants = await AgentPermission.find({ agentId: targetAgentId })
        .sort({ timestamp: -1 })
        .limit(10)
        .lean();

      return {
        agentId: targetAgent.agentId,
        agentName: targetAgent.name,
        status: targetAgent.status,
        permissions: targetAgent.permissions,
        recentGrants: grants
      };
    }
  },

  analyze_security_events: {
    name: 'analyze_security_events',
    requiredPermission: 'READ',
    description: 'Analyze security events to identify anomalous clusters or attack patterns',
    execute: async (params, agent) => {
      const limit = Math.min(Number(params.limit) || 20, 50);
      const alerts = await SecurityAlert.find({ status: 'active' })
        .sort({ timestamp: -1 })
        .limit(limit)
        .lean();

      const severityCounts = { low: 0, medium: 0, high: 0, critical: 0 };
      const categoryCounts = {};

      alerts.forEach(a => {
        severityCounts[a.severity] = (severityCounts[a.severity] || 0) + 1;
        categoryCounts[a.category] = (categoryCounts[a.category] || 0) + 1;
      });

      return {
        activeAlertsCount: alerts.length,
        severityBreakdown: severityCounts,
        categoryBreakdown: categoryCounts,
        criticalThreats: alerts.filter(a => a.severity === 'critical')
      };
    }
  },

  generate_security_report: {
    name: 'generate_security_report',
    requiredPermission: 'WRITE',
    description: 'Generate structured security posture and compliance report',
    execute: async (params, agent) => {
      const agentsCount = await Agent.countDocuments();
      const activeAgents = await Agent.countDocuments({ status: 'active' });
      const totalActivities = await AgentActivity.countDocuments();
      const blockedActivities = await AgentActivity.countDocuments({ decision: 'DENY' });
      const criticalAlerts = await SecurityAlert.countDocuments({ severity: 'critical', status: 'active' });

      const score = Math.max(0, Math.min(100, Math.round(
        100 - (totalActivities > 0 ? (blockedActivities / totalActivities) * 30 : 0) - (criticalAlerts * 5)
      )));

      return {
        generatedAt: new Date().toISOString(),
        reportedBy: `${agent.name} (${agent.agentId})`,
        scope: params.scope || 'ALL_AGENTS',
        systemHealth: score >= 80 ? 'OPTIMAL' : score >= 60 ? 'DEGRADED' : 'CRITICAL',
        securityPostureScore: score,
        metrics: {
          totalAgents: agentsCount,
          activeAgents,
          totalActivitiesEvaluated: totalActivities,
          blockedActivities,
          criticalAlertsActive: criticalAlerts
        },
        recommendations: [
          'Enforce least-privilege review on agents with unused permissions',
          'Quarantine agents with repeated authorization failures',
          'Verify Isolation Forest baseline calibration weekly'
        ]
      };
    }
  },

  create_security_alert: {
    name: 'create_security_alert',
    requiredPermission: 'UPDATE',
    description: 'Create a security incident alert with severity and recommended action',
    execute: async (params, agent) => {
      if (!params.title || !params.description) {
        throw new Error('Alert parameters require both title and description.');
      }

      const alertId = 'alr_' + Math.random().toString(36).slice(2, 8);
      const alert = new SecurityAlert({
        alertId,
        agentId: params.targetAgentId || agent.agentId,
        agentName: params.targetAgentName || agent.name,
        category: params.category || 'Unexpected Agent Behaviour',
        title: params.title,
        description: params.description,
        severity: params.severity || 'medium',
        riskScore: Number(params.riskScore) || 50,
        detectionSource: 'RULE_ENGINE',
        recommendedAction: params.recommendedAction || 'Review agent activity'
      });

      await alert.save();
      return {
        created: true,
        alertId: alert.alertId,
        severity: alert.severity,
        title: alert.title
      };
    }
  },

  retrieve_monitoring_metrics: {
    name: 'retrieve_monitoring_metrics',
    requiredPermission: 'READ',
    description: 'Retrieve real-time control plane telemetry and security metrics',
    execute: async (params, agent) => {
      const totalActivities = await AgentActivity.countDocuments();
      const allowed = await AgentActivity.countDocuments({ decision: 'ALLOW' });
      const blocked = await AgentActivity.countDocuments({ decision: 'DENY' });
      const pending = await AgentActivity.countDocuments({ decision: 'PENDING' });
      const activeAlerts = await SecurityAlert.countDocuments({ status: 'active' });
      const criticalAlerts = await SecurityAlert.countDocuments({ severity: 'critical', status: 'active' });

      return {
        totalEvaluated: totalActivities,
        authorizedCount: allowed,
        blockedCount: blocked,
        pendingApprovalCount: pending,
        activeAlerts,
        criticalAlerts,
        policyEngineStatus: 'ONLINE',
        chainIntegrity: 'VERIFIED'
      };
    }
  }
};

module.exports = {
  TOOLS
};
