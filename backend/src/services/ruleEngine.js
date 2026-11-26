/**
 * Deterministic Cybersecurity Rule Engine
 * Enforces security rules P-01 through P-08 alongside Isolation Forest ML
 */

const SENSITIVE_PATTERNS = /secret|password|token|payment|pii|vault|admin|root|\.env|dump|transfer|ledger|credit_card|ssn/i;
const ALLOWED_API_HOSTS = [
  'api.vendor.io',
  'partner-x.io',
  'api.stripe.com',
  'localhost',
  '127.0.0.1'
];

class RuleEngine {
  constructor() {
    this.rules = [
      { id: 'P-01', name: 'Least Privilege Enforcement', severity: 'critical', weight: 35 },
      { id: 'P-02', name: 'Payment Value Threshold', severity: 'high', weight: 25 },
      { id: 'P-03', name: 'Destructive Action Protection', severity: 'high', weight: 30 },
      { id: 'P-04', name: 'Excessive Request Frequency', severity: 'high', weight: 25 },
      { id: 'P-05', name: 'Repeated Authorization Denials', severity: 'critical', weight: 35 },
      { id: 'P-06', name: 'Off-Hours Sensitive Operations', severity: 'medium', weight: 15 },
      { id: 'P-07', name: 'Network Destination Allowlist', severity: 'critical', weight: 35 },
      { id: 'P-08', name: 'Emergency Freeze / Unapproved Agent Execution', severity: 'critical', weight: 50 }
    ];
  }

  /**
   * Evaluate a proposed action against deterministic security rules
   * @param {Object} context
   * @param {Object} context.agent - Agent document
   * @param {string} context.action - 'READ'|'WRITE'|'DELETE'|'UPDATE'|'API'|'CUSTOMER_DATA'|'PAYMENT'
   * @param {string} context.resource - Target resource path or URI
   * @param {number} context.amount - Numerical value for payments
   * @param {number} [context.hour] - Hour of day (0-23)
   * @param {number} [context.recentRequestsIn60s] - Count of recent requests
   * @param {number} [context.recentDenialsIn300s] - Count of recent denials
   * @param {boolean} [context.isGlobalFrozen] - Global emergency freeze state
   */
  evaluate(context) {
    const violations = [];
    const steps = [];
    let hardDenyReason = null;
    let requiresHumanApproval = null;

    const {
      agent,
      action,
      resource = '',
      amount = 0,
      hour = new Date().getHours(),
      recentRequestsIn60s = 0,
      recentDenialsIn300s = 0,
      isGlobalFrozen = false
    } = context;

    // RULE P-08: Global Freeze & Agent Approval Status
    if (isGlobalFrozen) {
      hardDenyReason = 'Global emergency freeze kill-switch engaged. All agent operations are halted.';
      violations.push({
        ruleId: 'P-08',
        name: 'Emergency Freeze',
        severity: 'critical',
        weight: 50,
        description: hardDenyReason,
        recommendedAction: 'Wait for administrator to disengage emergency freeze'
      });
      steps.push({ t: 'Identity & Status', s: 'fail', d: hardDenyReason });
    } else if (!agent) {
      hardDenyReason = 'Unregistered agent identity. Unknown agent token.';
      violations.push({
        ruleId: 'P-08',
        name: 'Unregistered Agent Identity',
        severity: 'critical',
        weight: 50,
        description: hardDenyReason,
        recommendedAction: 'Register agent and obtain signed token'
      });
      steps.push({ t: 'Identity & Status', s: 'fail', d: hardDenyReason });
    } else if (agent.status !== 'active' && agent.status !== 'approved' && agent.status !== 'running') {
      hardDenyReason = `Agent status is '${agent.status}'. Execution blocked until authorized by administrator.`;
      violations.push({
        ruleId: 'P-08',
        name: 'Unapproved Agent Execution',
        severity: 'critical',
        weight: 40,
        description: hardDenyReason,
        recommendedAction: 'Approve agent in control plane before execution'
      });
      steps.push({ t: 'Identity & Status', s: 'fail', d: hardDenyReason });
    } else {
      steps.push({ t: 'Identity & Status', s: 'pass', d: `Verified active token for ${agent.name} (${agent.agentId})` });
    }

    // RULE P-01: Least Privilege / Permission Registry Check
    const hasPermission = agent && agent.permissions && agent.permissions[action] === true;
    if (!hasPermission) {
      const msg = `Capability '${action}' is not granted to agent '${agent ? agent.name : 'Unknown'}' in permission registry.`;
      if (!hardDenyReason) hardDenyReason = msg;
      violations.push({
        ruleId: 'P-01',
        name: 'Least Privilege Enforcement',
        severity: 'critical',
        weight: 35,
        description: msg,
        recommendedAction: 'Grant capability explicitly in Permission Registry or abort operation'
      });
      steps.push({ t: 'Permission Registry', s: 'fail', d: msg });
    } else {
      steps.push({ t: 'Permission Registry', s: 'pass', d: `Capability '${action}' granted by explicit policy` });
    }

    // RULE P-02: Payment Value Threshold (payments > $500 require human sign-off)
    if (action === 'PAYMENT' && Number(amount) > 500) {
      requiresHumanApproval = `Payment amount of $${amount.toLocaleString()} exceeds the $500 auto-approval threshold (Rule P-02).`;
      violations.push({
        ruleId: 'P-02',
        name: 'Payment Value Threshold',
        severity: 'high',
        weight: 25,
        description: requiresHumanApproval,
        recommendedAction: 'Require authorized human administrator approval in Approvals queue'
      });
    }

    // RULE P-03: Destructive Actions (DELETE operations require approval)
    if (action === 'DELETE') {
      const deleteMsg = `Destructive DELETE action on resource '${resource}' requires human authorization (Rule P-03).`;
      if (!requiresHumanApproval) requiresHumanApproval = deleteMsg;
      violations.push({
        ruleId: 'P-03',
        name: 'Destructive Action Protection',
        severity: 'high',
        weight: 30,
        description: deleteMsg,
        recommendedAction: 'Require human confirmation before permanent deletion'
      });
    }

    // RULE P-04: Excessive Request Frequency (> 15 req/min)
    if (recentRequestsIn60s > 15) {
      const freqMsg = `Request rate of ${recentRequestsIn60s} req/min exceeds threshold of 15 req/min.`;
      violations.push({
        ruleId: 'P-04',
        name: 'Excessive Request Frequency',
        severity: recentRequestsIn60s > 25 ? 'critical' : 'high',
        weight: recentRequestsIn60s > 25 ? 35 : 20,
        description: freqMsg,
        recommendedAction: 'Throttle agent calls and inspect for runaway loop'
      });
    }

    // RULE P-05: Repeated Authorization Denials (>= 3 denials in 5 minutes)
    if (recentDenialsIn300s >= 3) {
      const denialMsg = `Detected ${recentDenialsIn300s} authorization failures within 5 minutes. Potential privilege probe.`;
      violations.push({
        ruleId: 'P-05',
        name: 'Repeated Authorization Denials',
        severity: 'critical',
        weight: 35,
        description: denialMsg,
        recommendedAction: 'Quarantine agent immediately and alert security operations'
      });
    }

    // RULE P-06: Off-Hours Access for Sensitive Actions (22:00 - 06:00)
    const isOffHours = hour < 6 || hour >= 22;
    if (isOffHours && (action === 'PAYMENT' || action === 'CUSTOMER_DATA')) {
      violations.push({
        ruleId: 'P-06',
        name: 'Off-Hours Sensitive Operations',
        severity: 'medium',
        weight: 15,
        description: `Sensitive action '${action}' requested at ${String(hour).padStart(2, '0')}:00 outside standard operational window (06:00-22:00).`,
        recommendedAction: 'Log high-priority audit event and verify schedule authorization'
      });
    }

    // RULE P-07: Network Destination Allowlist for API calls
    if (action === 'API') {
      let host = '';
      try {
        const parsedUrl = new URL(resource);
        host = parsedUrl.hostname;
      } catch {
        const match = resource.match(/^https?:\/\/([^/:]+)/);
        host = match ? match[1] : resource;
      }

      const isAllowed = ALLOWED_API_HOSTS.some(allowed => host === allowed || host.endsWith('.' + allowed));
      if (!isAllowed) {
        const netMsg = `Outbound API destination '${host || resource}' is not on the sanctioned network allowlist (Rule P-07).`;
        if (!hardDenyReason) hardDenyReason = netMsg;
        violations.push({
          ruleId: 'P-07',
          name: 'Network Destination Allowlist',
          severity: 'critical',
          weight: 35,
          description: netMsg,
          recommendedAction: 'Block egress traffic and quarantine agent'
        });
        steps.push({ t: 'Network Allowlist', s: 'fail', d: netMsg });
      } else {
        steps.push({ t: 'Network Allowlist', s: 'pass', d: `Destination '${host}' is on approved allowlist` });
      }
    }

    // Check sensitive pattern match in resource name
    const matchesSensitive = SENSITIVE_PATTERNS.test(resource);
    if (matchesSensitive && action !== 'PAYMENT' && action !== 'CUSTOMER_DATA') {
      violations.push({
        ruleId: 'PATTERN-01',
        name: 'Sensitive Resource Pattern Match',
        severity: 'medium',
        weight: 12,
        description: `Target resource '${resource}' matches sensitive data signature.`,
        recommendedAction: 'Audit resource access pattern'
      });
    }

    // Summarize policy steps
    steps.push({
      t: 'Policy Rules (OPA-compatible)',
      s: hardDenyReason ? 'fail' : (requiresHumanApproval || violations.length > 0 ? 'warn' : 'pass'),
      d: violations.length > 0
        ? violations.map(v => `${v.ruleId}: ${v.name}`).join(' | ')
        : 'All 8 deterministic security rules passed cleanly'
    });

    return {
      passed: !hardDenyReason && !requiresHumanApproval,
      hardDenyReason,
      requiresHumanApproval,
      violations,
      steps,
      matchesSensitive
    };
  }
}

module.exports = new RuleEngine();
