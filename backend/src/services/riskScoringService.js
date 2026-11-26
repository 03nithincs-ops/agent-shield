/**
 * Centralized Risk Scoring Service
 * 
 * Transparent, Explainable Formula:
 * 
 * Composite Risk (0 - 100) =
 *   (Agent Baseline Risk * 0.25)
 *   + (Isolation Forest ML Anomaly Score * 30)
 *   + (Deterministic Rule Violations Weight, capped at 35)
 *   + (Permission & Capability Inherent Risk, 4 to 24)
 *   + (Recent Authorization Failures Penalty, min(20, denials * 6))
 *   + (Sensitive Resource Pattern Penalty, 8)
 * 
 * Risk Tiers:
 *   - LOW:      0 - 39
 *   - MEDIUM:  40 - 69
 *   - HIGH:    70 - 79
 *   - CRITICAL: 80 - 100 (triggers auto-block / quarantine)
 */

const PERMISSION_WEIGHTS = {
  READ: 4,
  WRITE: 10,
  UPDATE: 8,
  DELETE: 20,
  API: 8,
  CUSTOMER_DATA: 16,
  PAYMENT: 24
};

class RiskScoringService {
  /**
   * Calculate composite risk score and generate breakdown
   * @param {Object} params
   * @param {number} params.agentBaseline - Initial risk baseline (0-100)
   * @param {number} params.mlAnomalyScore - Isolation Forest anomaly output (0.0 to 1.0)
   * @param {boolean} params.isAnomaly - Isolation Forest boolean flag
   * @param {Array} params.ruleViolations - Violations from ruleEngine
   * @param {string} params.action - Capability / action attempted
   * @param {number} params.recentDenialsCount - Number of recent denials
   * @param {boolean} params.matchesSensitive - Matches sensitive pattern
   */
  calculateRisk(params) {
    const {
      agentBaseline = 15,
      mlAnomalyScore = 0.1,
      isAnomaly = false,
      ruleViolations = [],
      action = 'READ',
      recentDenialsCount = 0,
      matchesSensitive = false
    } = params;

    // Component 1: Baseline contribution (max 25 pts)
    const baselineContribution = Math.round(agentBaseline * 0.25);

    // Component 2: ML Isolation Forest contribution (max 30 pts)
    // mlAnomalyScore normalized from 0.0-1.0
    const mlContribution = Math.round(Math.min(1.0, Math.max(0, mlAnomalyScore)) * 30);

    // Component 3: Rule violations contribution (max 35 pts)
    const rawViolationsSum = ruleViolations.reduce((sum, v) => sum + (v.weight || 10), 0);
    const rulesContribution = Math.min(35, rawViolationsSum);

    // Component 4: Inherent capability risk (4 - 24 pts)
    const capabilityContribution = PERMISSION_WEIGHTS[action] || 6;

    // Component 5: Recent denial history penalty (max 20 pts)
    const denialsPenalty = Math.min(20, recentDenialsCount * 6);

    // Component 6: Sensitive resource match penalty (8 pts)
    const sensitivePenalty = matchesSensitive ? 8 : 0;

    // Composite total (clamped to 0 - 100)
    let totalScore = baselineContribution + mlContribution + rulesContribution + capabilityContribution + denialsPenalty + sensitivePenalty;
    totalScore = Math.max(0, Math.min(100, Math.round(totalScore)));

    // Categorization
    let category = 'LOW';
    let color = '#34d399';
    if (totalScore >= 80) {
      category = 'CRITICAL';
      color = '#fb7185';
    } else if (totalScore >= 70) {
      category = 'HIGH';
      color = '#fb923c';
    } else if (totalScore >= 40) {
      category = 'MEDIUM';
      color = '#fbbf24';
    }

    return {
      score: totalScore,
      category,
      color,
      breakdown: {
        agentBaseline: {
          value: agentBaseline,
          contribution: baselineContribution,
          formula: 'baseline * 0.25'
        },
        isolationForestML: {
          isAnomaly,
          anomalyScore: mlAnomalyScore,
          contribution: mlContribution,
          formula: 'anomalyScore * 30'
        },
        ruleViolations: {
          count: ruleViolations.length,
          violations: ruleViolations.map(v => ({ id: v.ruleId, name: v.name, weight: v.weight })),
          contribution: rulesContribution,
          formula: 'min(35, sum(violation_weights))'
        },
        capabilityRisk: {
          action,
          contribution: capabilityContribution,
          formula: `inherent_weight(${action})`
        },
        historyPenalties: {
          recentDenialsCount,
          contribution: denialsPenalty,
          formula: 'min(20, denials * 6)'
        },
        sensitivePatternPenalty: {
          matched: matchesSensitive,
          contribution: sensitivePenalty
        }
      },
      explanation: `Composite risk ${totalScore}/100 (${category}): Baseline(${baselineContribution}) + ML(${mlContribution}) + Rules(${rulesContribution}) + Capability(${capabilityContribution}) + History(${denialsPenalty}) + Sensitive(${sensitivePenalty})`
    };
  }
}

module.exports = new RiskScoringService();
