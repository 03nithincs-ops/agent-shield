process.env.PORT = '5003';
const path = require('path');
const { spawn } = require('child_process');
const axios = require(path.resolve(__dirname, '../backend/node_modules/axios'));
const { startServer, server } = require('../backend/src/server');

async function runE2ETests() {
  console.log('===============================================================');
  console.log('  AGENT SHIELD — COMPREHENSIVE END-TO-END VALIDATION SUITE    ');
  console.log('===============================================================\n');

  let passed = 0;
  let failed = 0;
  let mlProcess = null;

  function assert(condition, testName, details = '') {
    if (condition) {
      console.log(`  [PASS] ${testName}`);
      passed++;
    } else {
      console.error(`  [FAIL] ${testName} - ${details}`);
      failed++;
    }
  }

  try {
    console.log('[STAGE 0] Starting Python Isolation Forest ML Service...');
    const pythonExe = 'C:\\Users\\NITHIN C S\\.gemini\\antigravity\\scratch\\agent-shield\\.venv\\Scripts\\python.exe';
    mlProcess = spawn(pythonExe, ['run_ml.py'], {
      cwd: path.resolve(__dirname, '../ml-service'),
      stdio: 'inherit'
    });
    
    // Poll ML service until ready
    let mlOnline = false;
    for (let i = 0; i < 20; i++) {
      try {
        const mlHealth = await axios.get('http://127.0.0.1:8001/health', { timeout: 1000 });
        if (mlHealth.data.status === 'healthy') {
          mlOnline = true;
          break;
        }
      } catch {
        await new Promise(r => setTimeout(r, 600));
      }
    }
    assert(mlOnline, 'Python Isolation Forest service online on http://127.0.0.1:8001');

    console.log('\n[STAGE 1] Starting Express & Database Server...');
    await startServer();
    await new Promise(r => setTimeout(r, 1500));
    const baseUrl = 'http://localhost:5003/api';

    // 1. Health check
    const health = await axios.get(`${baseUrl}/health`);
    assert(health.data.status === 'healthy', 'Backend /api/health responds healthy');

    // 2. Authentication & Security
    console.log('\n[STAGE 2] Testing Authentication & RBAC...');
    // Login with bad password -> expect 401
    try {
      await axios.post(`${baseUrl}/auth/login`, {
        email: 'admin@agentshield.local',
        password: 'WrongPassword!'
      });
      assert(false, 'Reject invalid login credentials');
    } catch (err) {
      assert(err.response?.status === 401, 'Reject invalid login credentials (HTTP 401)');
    }

    // Valid login
    const loginRes = await axios.post(`${baseUrl}/auth/login`, {
      email: 'admin@agentshield.local',
      password: 'Admin123!'
    });
    assert(loginRes.data.success && !!loginRes.data.token, 'Admin authentication succeeds with JWT');
    const token = loginRes.data.token;
    const authHeaders = { headers: { Authorization: `Bearer ${token}` } };

    // Get current user
    const meRes = await axios.get(`${baseUrl}/auth/me`, authHeaders);
    assert(meRes.data.user.role === 'ADMIN', 'Current user endpoint returns ADMIN profile');

    // 3. Agent Lifecycle & Approval Enforcement
    console.log('\n[STAGE 3] Testing Agent Lifecycle & Controlled Execution...');
    // Create new agent -> starts in pending_approval
    const createAgentRes = await axios.post(`${baseUrl}/agents`, {
      name: 'E2E-Test-Agent',
      description: 'Test agent for security control plane',
      objective: 'Monitor security telemetry and execute read operations',
      instructions: 'Operate under strict least privilege. Execute only permitted tools.',
      allowedTools: ['read_security_logs'],
      permissions: { READ: true, WRITE: false, DELETE: false, API: false, CUSTOMER_DATA: false, PAYMENT: false, UPDATE: false },
      riskBase: 12
    }, authHeaders);
    const newAgent = createAgentRes.data.agent;
    assert(newAgent.status === 'pending_approval', 'Newly provisioned agent starts in pending_approval state');

    // Attempt to execute unapproved agent -> must fail with 403
    try {
      await axios.post(`${baseUrl}/agents/${newAgent.agentId}/execute`, {
        taskName: 'Unapproved execution check',
        toolName: 'read_security_logs',
        parameters: {}
      }, authHeaders);
      assert(false, 'Unapproved agent execution blocked');
    } catch (err) {
      assert(err.response?.status === 403, 'Unapproved agent cannot execute tools (HTTP 403)');
    }

    // Approve the agent
    const approveRes = await axios.post(`${baseUrl}/agents/${newAgent.agentId}/approve`, {}, authHeaders);
    assert(approveRes.data.agent.status === 'approved', 'Human administrator can approve agent');

    // Execute registered tool on approved agent -> succeeds
    const execRes = await axios.post(`${baseUrl}/agents/${newAgent.agentId}/execute`, {
      taskName: 'Authorized security log read',
      toolName: 'read_security_logs',
      parameters: { limit: 5 }
    }, authHeaders);
    assert(execRes.data.success && execRes.data.result.toolName === 'read_security_logs', 'Controlled runtime executes registered tool');

    // Attempt to execute an unauthorized tool -> must fail
    try {
      await axios.post(`${baseUrl}/agents/${newAgent.agentId}/execute`, {
        taskName: 'Unauthorized tool test',
        toolName: 'generate_security_report', // requires WRITE, which is false
        parameters: {}
      }, authHeaders);
      assert(false, 'Unauthorized tool execution denied');
    } catch (err) {
      assert(err.response?.status === 403, 'Unauthorized tool access denied by least privilege (HTTP 403)');
    }

    // 4. Deterministic Cybersecurity Rule Engine
    console.log('\n[STAGE 4] Testing Cybersecurity Rule Engine & Risk Scoring...');
    // Rule P-02: Payment > $500 requires approval
    const simPayRes = await axios.post(`${baseUrl}/monitoring/simulate`, {
      agentId: newAgent.agentId,
      action: 'PAYMENT',
      resource: 'payment.transfer:wire',
      amount: 2500,
      commit: false
    }, authHeaders);
    assert(simPayRes.data.decision === 'DENY' || simPayRes.data.decision === 'PENDING', 'Payment threshold rule triggers PENDING/DENY for $2,500');

    // Rule P-07: Unapproved outbound API host
    const simApiRes = await axios.post(`${baseUrl}/monitoring/simulate`, {
      agentId: newAgent.agentId,
      action: 'API',
      resource: 'https://evil-unapproved-exfil.xyz/steal',
      commit: false
    }, authHeaders);
    assert(simApiRes.data.decision === 'DENY', 'Network Destination Allowlist rule blocks unapproved egress (Rule P-07)');

    // 5. Emergency Global Kill Switch
    console.log('\n[STAGE 5] Testing Emergency Global Freeze Switch...');
    await axios.post(`${baseUrl}/security/freeze`, { freeze: true }, authHeaders);
    const simFrozenRes = await axios.post(`${baseUrl}/monitoring/simulate`, {
      agentId: newAgent.agentId,
      action: 'READ',
      resource: '/data/ledger_q3.csv',
      commit: false
    }, authHeaders);
    assert(simFrozenRes.data.decision === 'DENY' && simFrozenRes.data.reason.includes('freeze'), 'Emergency freeze halts all operations (Rule P-08)');
    await axios.post(`${baseUrl}/security/freeze`, { freeze: false }, authHeaders);

    // 6. Cryptographic SHA-256 Audit Chain
    console.log('\n[STAGE 6] Testing Tamper-Evident SHA-256 Audit Log...');
    const auditVerifyRes = await axios.get(`${baseUrl}/security/audit-logs/verify`, authHeaders);
    assert(auditVerifyRes.data.verification.ok === true, `Cryptographic SHA-256 chain verified (${auditVerifyRes.data.verification.count} records intact)`);

    // 7. AI Health & Model Check
    console.log('\n[STAGE 7] Testing Ollama & Qwen3 Service Status...');
    const aiHealthRes = await axios.get(`${baseUrl}/ai/health`);
    assert(aiHealthRes.data.success === true, 'AI Health endpoint reports accurate status');

    // 8. Frontend Serving
    console.log('\n[STAGE 8] Testing Frontend Dashboard Serving...');
    const frontendRes = await axios.get('http://localhost:5000/');
    assert(frontendRes.data.includes('Agent Shield'), 'Frontend HTML served with Agent Shield control plane UI');

    console.log('\n===============================================================');
    console.log(`  TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
    console.log('===============================================================\n');

    if (mlProcess) mlProcess.kill();

    if (failed === 0) {
      console.log('>>> ALL END-TO-END VALIDATION CHECKS PASSED PERFECTLY! <<<');
      process.exit(0);
    } else {
      process.exit(1);
    }
  } catch (error) {
    if (mlProcess) mlProcess.kill();
    console.error('Fatal Test Suite Error:', error.response?.data || error.message);
    process.exit(1);
  }
}

runE2ETests();
