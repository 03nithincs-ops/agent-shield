const { z } = require('zod');

const VALID_TOOLS = [
  'read_security_logs',
  'analyze_api_stats',
  'check_agent_permissions',
  'analyze_security_events',
  'generate_security_report',
  'create_security_alert',
  'retrieve_monitoring_metrics'
];

const agentBlueprintSchema = z.object({
  name: z.string().min(2).max(64),
  description: z.string().min(5).max(500),
  objective: z.string().min(5).max(500),
  instructions: z.string().min(5).max(2000),
  model: z.string().default('qwen3'),
  allowedTools: z.array(z.string()).refine(
    tools => tools.every(t => VALID_TOOLS.includes(t)),
    { message: `Allowed tools must only contain registered tools: ${VALID_TOOLS.join(', ')}` }
  ),
  permissions: z.object({
    READ: z.boolean().default(true),
    WRITE: z.boolean().default(false),
    DELETE: z.boolean().default(false),
    UPDATE: z.boolean().default(false),
    API: z.boolean().default(false),
    CUSTOMER_DATA: z.boolean().default(false),
    PAYMENT: z.boolean().default(false)
  }),
  riskLevel: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).default('LOW'),
  executionSettings: z.object({
    maxExecutionTimeMs: z.number().min(1000).max(60000).default(30000),
    maxRequestsPerMin: z.number().min(1).max(120).default(15),
    requireHumanApprovalForSensitive: z.boolean().default(true)
  }).default({}),
  safetyRestrictions: z.array(z.string()).default([])
});

const createAgentSchema = agentBlueprintSchema.extend({
  riskBase: z.number().min(0).max(100).optional()
});

const executeTaskSchema = z.object({
  taskName: z.string().min(1),
  toolName: z.string().refine(t => VALID_TOOLS.includes(t), {
    message: `Invalid tool. Must be one of: ${VALID_TOOLS.join(', ')}`
  }),
  parameters: z.record(z.any()).default({})
});

const simulateRequestSchema = z.object({
  agentId: z.string().min(1),
  action: z.enum(['READ', 'WRITE', 'DELETE', 'UPDATE', 'API', 'CUSTOMER_DATA', 'PAYMENT']),
  resource: z.string().min(1),
  amount: z.number().optional().default(0),
  hour: z.number().min(0).max(23).optional()
});

module.exports = {
  VALID_TOOLS,
  agentBlueprintSchema,
  createAgentSchema,
  executeTaskSchema,
  simulateRequestSchema
};
