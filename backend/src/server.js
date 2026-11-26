const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');

const { PORT, NODE_ENV, FRONTEND_URL } = require('./config/env');
const { connectDB } = require('./config/db');
const { apiLimiter } = require('./middleware/rateLimiter');
const errorHandler = require('./middleware/errorHandler');
const setupSockets = require('./sockets/socketHandler');
const agentRuntime = require('./services/agentRuntime');

// Import Models
const User = require('./models/User');
const Agent = require('./models/Agent');
const AgentActivity = require('./models/AgentActivity');
const SecurityAlert = require('./models/SecurityAlert');
const AgentPermission = require('./models/AgentPermission');
const auditService = require('./services/auditService');

// Import Routes
const authRoutes = require('./routes/authRoutes');
const aiRoutes = require('./routes/aiRoutes');
const agentRoutes = require('./routes/agentRoutes');
const securityRoutes = require('./routes/securityRoutes');
const monitoringRoutes = require('./routes/monitoringRoutes');

const app = express();
const server = http.createServer(app);

// Initialize Socket.IO
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE']
  }
});

setupSockets(io);
agentRuntime.setSocketIO(io);

// Security & Utility Middleware
app.use(helmet({
  contentSecurityPolicy: false // Allow inline scripts and canvas rendering for dashboard
}));
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/api/', apiLimiter);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    version: '1.0.0',
    service: 'Agent Shield Control Plane Backend'
  });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/agents', agentRoutes);
app.use('/api/security', securityRoutes);
app.use('/api/monitoring', monitoringRoutes);

// Serve frontend static files if present
const frontendDist = path.resolve(__dirname, '../../frontend');
app.use(express.static(frontendDist));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  res.sendFile(path.join(frontendDist, 'index.html'));
});

// Centralized error handling
app.use(errorHandler);

// Seed initial database state if empty
async function seedInitialData() {
  try {
    const userCount = await User.countDocuments();
    if (userCount === 0) {
      console.log('[Seed] Seeding initial users...');
      await User.create([
        {
          name: 'Root Admin',
          email: 'admin@agentshield.local',
          password: 'Admin123!',
          role: 'ADMIN',
          status: 'active'
        },
        {
          name: 'Ana Analyst',
          email: 'analyst@agentshield.local',
          password: 'Analyst123!',
          role: 'ANALYST',
          status: 'active'
        }
      ]);
      console.log('[Seed] Initial users created.');
    }

    const agentCount = await Agent.countDocuments();
    if (agentCount === 0) {
      console.log('[Seed] Seeding initial agents...');
      const seedAgents = [
        { id: 'agt_7f2a', name: 'Research-Ops-7', model: 'qwen3', base: 8, perms: ['READ', 'API', 'CUSTOMER_DATA'], tools: ['read_security_logs', 'analyze_api_stats', 'retrieve_monitoring_metrics'] },
        { id: 'agt_3c91', name: 'Finance-Agent-2', model: 'qwen3', base: 22, perms: ['READ', 'WRITE', 'UPDATE', 'API', 'CUSTOMER_DATA', 'PAYMENT'], tools: ['read_security_logs', 'analyze_api_stats', 'check_agent_permissions'] },
        { id: 'agt_9b04', name: 'Support-Triage-1', model: 'qwen3', base: 15, perms: ['READ', 'WRITE', 'API', 'CUSTOMER_DATA'], tools: ['read_security_logs', 'generate_security_report'] },
        { id: 'agt_1d55', name: 'Deploy-Bot-4', model: 'qwen3', base: 35, perms: ['READ', 'WRITE', 'UPDATE', 'DELETE', 'API'], tools: ['read_security_logs', 'check_agent_permissions'] },
        { id: 'agt_5a18', name: 'DataSync-9', model: 'qwen3', base: 14, perms: ['READ', 'API', 'UPDATE'], tools: ['read_security_logs', 'analyze_api_stats'] },
        { id: 'agt_6e47', name: 'Legacy-Scraper-3', model: 'qwen3', base: 55, perms: ['READ', 'API'], tools: ['read_security_logs'] },
        { id: 'agt_2b83', name: 'Analytics-Bot-5', model: 'qwen3', base: 18, perms: ['READ', 'UPDATE', 'CUSTOMER_DATA'], tools: ['read_security_logs', 'generate_security_report'] },
        { id: 'agt_8f12', name: 'Billing-Orchestrator', model: 'qwen3', base: 26, perms: ['READ', 'UPDATE', 'PAYMENT', 'CUSTOMER_DATA'], tools: ['read_security_logs', 'retrieve_monitoring_metrics'] },
        { id: 'agt_4a77', name: 'Code-Reviewer-2', model: 'qwen3', base: 12, perms: ['READ', 'WRITE', 'UPDATE'], tools: ['read_security_logs', 'generate_security_report'] },
        { id: 'agt_9d30', name: 'Incident-Responder', model: 'qwen3', base: 20, perms: ['READ', 'API', 'DELETE', 'UPDATE'], tools: ['read_security_logs', 'analyze_security_events', 'create_security_alert'] },
        { id: 'agt_1c65', name: 'Marketing-Writer', model: 'qwen3', base: 6, perms: ['READ', 'WRITE'], tools: ['read_security_logs'] },
        { id: 'agt_7e29', name: 'Compliance-Auditor', model: 'qwen3', base: 10, perms: ['READ', 'CUSTOMER_DATA', 'UPDATE'], tools: ['read_security_logs', 'check_agent_permissions', 'generate_security_report'] }
      ];

      for (const a of seedAgents) {
        const permsObj = {
          READ: a.perms.includes('READ'),
          WRITE: a.perms.includes('WRITE'),
          DELETE: a.perms.includes('DELETE'),
          UPDATE: a.perms.includes('UPDATE'),
          API: a.perms.includes('API'),
          CUSTOMER_DATA: a.perms.includes('CUSTOMER_DATA'),
          PAYMENT: a.perms.includes('PAYMENT')
        };

        const agentDoc = new Agent({
          agentId: a.id,
          name: a.name,
          description: `Autonomous cybersecurity agent: ${a.name}`,
          model: a.model,
          status: 'active',
          riskBase: a.base,
          riskScore: a.base,
          seed: Math.floor(Math.random() * 1000000),
          allowedTools: a.tools,
          permissions: permsObj,
          safetyRestrictions: ['Do not bypass permission checks', 'Do not execute arbitrary code'],
          createdBy: 'admin@agentshield.local'
        });
        await agentDoc.save();

        for (const p of a.perms) {
          await new AgentPermission({
            grantId: 'g_' + Math.random().toString(36).slice(2, 8),
            agentId: a.id,
            permission: p,
            action: 'GRANT',
            grantedBy: 'admin@agentshield.local',
            reason: 'Baseline capability grant'
          }).save();
        }

        // Add initial activity and audit record
        const act = new AgentActivity({
          activityId: 'act_' + Math.random().toString(36).slice(2, 8),
          agentId: a.id,
          agentName: a.name,
          action: 'READ',
          resource: '/data/agents.json',
          decision: 'ALLOW',
          riskScore: a.base,
          reason: 'Initial baseline verification check passed'
        });
        await act.save();

        await auditService.recordEvent({
          agentId: a.id,
          agentName: a.name,
          action: 'INITIALIZE',
          resource: `agent://${a.id}`,
          decision: 'ALLOW',
          riskScore: a.base,
          reason: 'Agent initialized in active state'
        });
      }
      console.log('[Seed] 12 initial agents seeded with capabilities and audit logs.');

      // Add sample active alerts
      await SecurityAlert.create([
        {
          alertId: 'alr_019a',
          agentId: 'agt_6e47',
          agentName: 'Legacy-Scraper-3',
          category: 'Suspicious Resource Access',
          title: 'Suspicious Resource Access: /secrets/customer_dump.sql',
          description: 'Repeated attempts to read /secrets/customer_dump.sql outside its grant scope.',
          severity: 'critical',
          riskScore: 88,
          detectionSource: 'RULE_ENGINE',
          recommendedAction: 'Block request and review agent grant scope'
        },
        {
          alertId: 'alr_028b',
          agentId: 'agt_5a18',
          agentName: 'DataSync-9',
          category: 'Excessive API Requests',
          title: 'Excessive Request Frequency: api.vendor.io',
          description: '18 API calls in 60 seconds against https://api.vendor.io/v2/export.',
          severity: 'high',
          riskScore: 64,
          detectionSource: 'RULE_ENGINE',
          recommendedAction: 'Throttle agent to 15 req/min'
        },
        {
          alertId: 'alr_037c',
          agentId: 'agt_1d55',
          agentName: 'Deploy-Bot-4',
          category: 'Unexpected Agent Behaviour',
          title: 'Anomalous Action: DELETE on archive',
          description: 'First DELETE request observed on /data/archive_2022.csv.',
          severity: 'high',
          riskScore: 71,
          detectionSource: 'ISOLATION_FOREST',
          recommendedAction: 'Hold for human approval'
        }
      ]);
      console.log('[Seed] Initial security alerts seeded.');
    }
  } catch (error) {
    console.error('[Seed] Error seeding initial data:', error);
  }
}

// Start Server
async function startServer() {
  try {
    await connectDB();
    await seedInitialData();

    if (!server.listening) {
      server.listen(PORT, () => {
        console.log(`=======================================================`);
        console.log(`  AGENT SHIELD CONTROL PLANE BACKEND ACTIVE            `);
        console.log(`  HTTP Server: http://localhost:${PORT}                `);
        console.log(`  Socket.IO:   ws://localhost:${PORT}                  `);
        console.log(`  Mode:        ${NODE_ENV}                             `);
        console.log(`=======================================================`);
      });
    }
  } catch (error) {
    console.error('Fatal startup error:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  startServer();
}

module.exports = { app, server, startServer };
