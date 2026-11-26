process.env.PORT = '5002';
const path = require('path');
const { spawn } = require('child_process');
const axios = require(path.resolve(__dirname, '../backend/node_modules/axios'));
const { startServer, server } = require('../backend/src/server');
const auditService = require('../backend/src/services/auditService');

async function runLifecycleTests() {
  console.log('===============================================================');
  console.log('  AGENT SHIELD — AGENT LIFECYCLE & RECOVERY VALIDATION SUITE  ');
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
    console.log('[SETUP] Starting Python Isolation Forest ML Service...');
    const pythonExe = 'C:\\Users\\NITHIN C S\\.gemini\\antigravity\\scratch\\agent-shield\\.venv\\Scripts\\python.exe';
    mlProcess = spawn(pythonExe, ['run_ml.py'], {
      cwd: path.resolve(__dirname, '../ml-service'),
      stdio: 'inherit'
    });

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
    assert(mlOnline, 'Python ML Service online on :8001');

    console.log('\n[SETUP] Starting Backend Control Plane...');
    await startServer();
    await new Promise(r => setTimeout(r, 1200));
    const baseUrl = 'http://localhost:5002/api';

    // 1. Authenticate Admin and Analyst
    console.log('\n[STAGE 1] Authenticating Test Principals (Admin & Analyst)...');
    const adminLogin = await axios.post(`${baseUrl}/auth/login`, {
      email: 'admin@agentshield.local',
      password: 'Admin123!'
    });
    const adminToken = adminLogin.data.token;
    assert(adminToken && adminLogin.data.user.role === 'ADMIN', 'Admin login successful with role ADMIN');

    const analystLogin = await axios.post(`${baseUrl}/auth/login`, {
      email: 'analyst@agentshield.local',
      password: 'Analyst123!'
    });
    const analystToken = analystLogin.data.token;
    assert(analystToken && analystLogin.data.user.role === 'ANALYST', 'Analyst login successful with role ANALYST');

    const adminHeaders = { headers: { Authorization: `Bearer ${adminToken}` } };
    const analystHeaders = { headers: { Authorization: `Bearer ${analystToken}` } };

    // 2. Create a disposable test agent
    console.log('\n[STAGE 2] Creating Disposable Test Agent...');
    const testAgentPayload = {
      name: `Lifecycle-Test-Agent-${Date.now().toString().slice(-4)}`,
      description: 'Disposable agent for lifecycle and recovery testing',
      objective: 'Verify state machine enforcement',
      instructions: 'Do not bypass security checks',
      model: 'qwen3',
      riskBase: 18,
      allowedTools: ['read_security_logs', 'analyze_api_stats'],
      permissions: {
        READ: true,
        API: true,
        CUSTOMER_DATA: false,
        PAYMENT: false,
        WRITE: false,
        DELETE: false,
        UPDATE: false
      }
    };

    const createRes = await axios.post(`${baseUrl}/agents`, testAgentPayload, adminHeaders);
    const testAgent = createRes.data.agent;
    const testAgentId = testAgent.agentId;
    assert(testAgent.status === 'pending_approval', `New agent created in 'pending_approval' state (ID: ${testAgentId})`);

    // 3. Test Invalid Transition: pending_approval -> start
    console.log('\n[STAGE 3] Testing Invalid Transitions from pending_approval...');
    try {
      await axios.post(`${baseUrl}/agents/${testAgentId}/start`, {}, adminHeaders);
      assert(false, 'Cannot start agent in pending_approval state');
    } catch (err) {
      assert(err.response?.status === 400, 'Direct start from pending_approval is blocked (HTTP 400)');
    }

    // 4. Test Approval Workflow: pending_approval -> approved
    console.log('\n[STAGE 4] Human Approval Workflow...');
    const approveRes = await axios.post(`${baseUrl}/agents/${testAgentId}/approve`, { notes: 'Initial security inspection passed' }, adminHeaders);
    assert(approveRes.data.agent.status === 'approved', 'Agent transitioned pending_approval -> approved');

    // 5. Test Activation: approved -> active
    console.log('\n[STAGE 5] Activation: approved -> active...');
    const startRes = await axios.post(`${baseUrl}/agents/${testAgentId}/start`, {}, adminHeaders);
    assert(startRes.data.agent.status === 'active', 'Agent transitioned approved -> active');

    // 6. Test Task Execution under Active State
    console.log('\n[STAGE 6] Runtime Execution under Active State...');
    const execRes = await axios.post(`${baseUrl}/agents/${testAgentId}/execute`, {
      taskName: 'Security Log Inspection',
      toolName: 'read_security_logs',
      parameters: { limit: 5 }
    }, adminHeaders);
    assert(execRes.data.success === true, 'Controlled tool execution allowed in active state');

    // 7. Test Suspension / Quarantine
    console.log('\n[STAGE 7] Containment & Quarantine (active -> suspended)...');
    const suspendRes = await axios.post(`${baseUrl}/agents/${testAgentId}/suspend`, {
      reason: 'Automated containment test: excessive rate threshold'
    }, analystHeaders);
    assert(suspendRes.data.agent.status === 'suspended', 'Agent transitioned active -> suspended');

    // 8. Test Forbidden Transitions from suspended state
    console.log('\n[STAGE 8] Testing Strict Security Guards on Suspended Agent...');
    // Direct start must fail with 400
    try {
      await axios.post(`${baseUrl}/agents/${testAgentId}/start`, {}, adminHeaders);
      assert(false, 'Direct start of suspended agent should have thrown 400');
    } catch (err) {
      assert(
        err.response?.status === 400 && err.response.data.error.includes('suspended'),
        'Direct start from suspended state is blocked with HTTP 400 and recovery requirement message'
      );
    }

    // Direct approve must fail with 400
    try {
      await axios.post(`${baseUrl}/agents/${testAgentId}/approve`, {}, adminHeaders);
      assert(false, 'Direct approve of suspended agent should have thrown 400');
    } catch (err) {
      assert(
        err.response?.status === 400 && err.response.data.error.includes('/recover'),
        'Direct standard approval on suspended agent is blocked (must use /recover)'
      );
    }

    // 9. RBAC & Validation Checks on /recover Endpoint
    console.log('\n[STAGE 9] RBAC & Input Validation on POST /recover...');
    // Analyst trying to recover -> 403 Forbidden
    try {
      await axios.post(`${baseUrl}/agents/${testAgentId}/recover`, {
        justification: 'Analyst attempting recovery bypass'
      }, analystHeaders);
      assert(false, 'Analyst should not be permitted to recover suspended agent');
    } catch (err) {
      assert(err.response?.status === 403, 'Analyst recovery attempt rejected with HTTP 403 Forbidden');
    }

    // Admin attempting recovery with missing/insufficient justification (< 10 chars) -> 400
    try {
      await axios.post(`${baseUrl}/agents/${testAgentId}/recover`, {
        justification: 'short'
      }, adminHeaders);
      assert(false, 'Short justification should have thrown 400');
    } catch (err) {
      assert(
        err.response?.status === 400 && err.response.data.error.includes('10 characters'),
        'Meaningful justification requirement enforced (min 10 characters, HTTP 400)'
      );
    }

    // Attempting recovery on a non-suspended agent (test with approved/active agent)
    // We will verify this rule after recovering
    
    // 10. Valid Administrator-Authorized Recovery Workflow
    console.log('\n[STAGE 10] Authorizing Recovery by Administrator...');
    const recoverPayload = {
      justification: 'Root cause verified: external webhook burst mitigated; rate limit adjusted to 10 req/min.',
      mitigationNotes: 'Permissions re-verified; dangerous capabilities remain denied; baseline reassessed.'
    };
    const recoverRes = await axios.post(`${baseUrl}/agents/${testAgentId}/recover`, recoverPayload, adminHeaders);
    
    assert(recoverRes.data.success === true, 'Admin recovery authorized successfully');
    assert(
      recoverRes.data.agent.status === 'approved',
      "Crucial security requirement: Recovery transitions status to 'approved' (NEVER directly to 'active')"
    );
    const reassessedRisk = recoverRes.data.reassessment?.reassessedRiskScore ?? recoverRes.data.agent.riskScore;
    assert(
      reassessedRisk < 70,
      `Risk score normalized safely (${reassessedRisk}/100) based on permissions review`
    );
    assert(
      recoverRes.data.agent.permissions.PAYMENT === false && recoverRes.data.agent.permissions.CUSTOMER_DATA === false,
      'Least-privilege preserved: Dangerous capabilities were not auto-granted during recovery'
    );
    assert(
      recoverRes.data.agent.recoveryHistory?.length > 0,
      'Recovery history metadata recorded on agent document'
    );

    // Verify calling /recover on an already approved agent is rejected
    try {
      await axios.post(`${baseUrl}/agents/${testAgentId}/recover`, {
        justification: 'Duplicate recovery attempt'
      }, adminHeaders);
      assert(false, 'Calling /recover on non-suspended agent should fail');
    } catch (err) {
      assert(
        err.response?.status === 400 && err.response.data.error.includes('Only suspended agents'),
        'Calling /recover on non-suspended agent correctly rejected (HTTP 400)'
      );
    }

    // 11. Human-in-the-Loop Separate Activation (approved -> active)
    console.log('\n[STAGE 11] Human-in-the-Loop Activation After Recovery...');
    const reactivateRes = await axios.post(`${baseUrl}/agents/${testAgentId}/start`, {}, adminHeaders);
    assert(reactivateRes.data.agent.status === 'active', 'Agent safely reactivated into active state');

    // Execute task again to verify runtime works
    const execAfterRes = await axios.post(`${baseUrl}/agents/${testAgentId}/execute`, {
      taskName: 'Post Recovery Log Audit',
      toolName: 'read_security_logs',
      parameters: { limit: 2 }
    }, adminHeaders);
    assert(execAfterRes.data.success === true, 'Agent executes successfully in runtime after recovery');

    // 12. Permanent Revocation & Terminal State Enforcement
    console.log('\n[STAGE 12] Decommissioning & Terminal State (Revoked)...');
    const revokeRes = await axios.post(`${baseUrl}/agents/${testAgentId}/revoke`, {
      reason: 'End-of-lifecycle decommissioning for test agent'
    }, adminHeaders);
    assert(revokeRes.data.agent.status === 'revoked', "Agent transitioned to terminal 'revoked' status");

    // Cannot start revoked agent
    try {
      await axios.post(`${baseUrl}/agents/${testAgentId}/start`, {}, adminHeaders);
      assert(false, 'Revoked agent should not be startable');
    } catch (err) {
      assert(err.response?.status === 400 && err.response.data.error.includes('revoked'), 'Start blocked on revoked agent (HTTP 400)');
    }

    // Cannot recover revoked agent
    try {
      await axios.post(`${baseUrl}/agents/${testAgentId}/recover`, { justification: 'Attempting to revive revoked agent' }, adminHeaders);
      assert(false, 'Revoked agent should not be recoverable');
    } catch (err) {
      assert(err.response?.status === 400 && err.response.data.error.includes('permanently decommissioned'), 'Recovery blocked on revoked agent (HTTP 400)');
    }

    // 13. SHA-256 Tamper-Evident Audit Chain Verification
    console.log('\n[STAGE 13] Verifying SHA-256 Tamper-Evident Audit Trail...');
    const auditVerification = await auditService.verifyChain();
    assert(auditVerification.ok === true, `SHA-256 Chain integrity intact: ${auditVerification.message}`);
    assert(auditVerification.count > 0, `Audit log contains ${auditVerification.count} cryptographically sealed entries`);

    // Verify presence of lifecycle actions in the audit chain for this agent
    const AuditLog = require('../backend/src/models/AuditLog');
    const agentAuditLogs = await AuditLog.find({ agentId: testAgentId }).sort({ seq: 1 }).lean();
    const recordedActions = agentAuditLogs.map(l => l.action);
    console.log(`  Audit events recorded for ${testAgentId}:`, recordedActions.join(' -> '));

    assert(recordedActions.includes('CREATE_AGENT'), 'Audit chain recorded CREATE_AGENT');
    assert(recordedActions.includes('APPROVE_AGENT'), 'Audit chain recorded APPROVE_AGENT');
    assert(recordedActions.includes('START_AGENT'), 'Audit chain recorded START_AGENT (initial activation)');
    assert(recordedActions.includes('SUSPEND_AGENT'), 'Audit chain recorded SUSPEND_AGENT');
    assert(recordedActions.includes('RECOVER_AGENT'), 'Audit chain recorded RECOVER_AGENT');
    assert(recordedActions.filter(a => a === 'START_AGENT').length >= 2, 'Audit chain recorded second START_AGENT (reactivation)');
    assert(recordedActions.includes('REVOKE_AGENT'), 'Audit chain recorded REVOKE_AGENT');

    console.log('\n===============================================================');
    console.log(`  TEST RESULTS: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
    console.log('===============================================================');

  } catch (error) {
    console.error('\n[FATAL TEST RUNNER ERROR]:', error);
    failed++;
  } finally {
    if (mlProcess) {
      try { process.kill(mlProcess.pid); } catch {}
    }
    if (server) {
      try { server.close(); } catch {}
    }
    // Clean exit code
    process.exit(failed > 0 ? 1 : 0);
  }
}

runLifecycleTests();
