const axios = require('axios');
const { startServer, server } = require('../src/server');
const { disconnectDB } = require('../src/config/db');

async function testBackend() {
  console.log('--- Testing Backend Startup and Endpoints ---');
  try {
    // 1. Start server
    console.log('[0/7] Starting Express and MongoDB server...');
    await startServer();
    await new Promise(resolve => setTimeout(resolve, 1500));
    const baseUrl = 'http://localhost:5000/api';

    // 2. Test Health Check
    console.log('[1/7] Testing GET /api/health...');
    const healthRes = await axios.get(`${baseUrl}/health`);
    console.log('  -> Health response:', healthRes.data);

    // 3. Test Login with Admin
    console.log('[2/7] Testing POST /api/auth/login...');
    const loginRes = await axios.post(`${baseUrl}/auth/login`, {
      email: 'admin@agentshield.local',
      password: 'Admin123!'
    });
    console.log('  -> Login success:', loginRes.data.success, 'Token received:', !!loginRes.data.token);
    const token = loginRes.data.token;
    const authHeaders = { headers: { Authorization: `Bearer ${token}` } };

    // 4. Test Current User
    console.log('[3/7] Testing GET /api/auth/me...');
    const meRes = await axios.get(`${baseUrl}/auth/me`, authHeaders);
    console.log('  -> Current User:', meRes.data.user.email, 'Role:', meRes.data.user.role);

    // 5. Test List Agents
    console.log('[4/7] Testing GET /api/agents...');
    const agentsRes = await axios.get(`${baseUrl}/agents`, authHeaders);
    console.log('  -> Agents count:', agentsRes.data.count);

    // 6. Test Security Metrics
    console.log('[5/7] Testing GET /api/security/metrics...');
    const metricsRes = await axios.get(`${baseUrl}/security/metrics`, authHeaders);
    console.log('  -> Score:', metricsRes.data.score, 'Metrics:', metricsRes.data.metrics);

    // 7. Test SHA-256 Audit Chain Verification
    console.log('[6/7] Testing GET /api/security/audit-logs/verify...');
    const verifyRes = await axios.get(`${baseUrl}/security/audit-logs/verify`, authHeaders);
    console.log('  -> Chain verification result:', verifyRes.data.verification);

    // 8. Test AI Health
    console.log('[7/7] Testing GET /api/ai/health...');
    const aiHealth = await axios.get(`${baseUrl}/ai/health`);
    console.log('  -> AI Health:', aiHealth.data);

    console.log('\n>>> ALL BACKEND ENDPOINTS PASSED SUCCESSFULLY! <<<');
    process.exit(0);
  } catch (error) {
    console.error('Backend Test Failed:', error.response?.data || error.message);
    process.exit(1);
  }
}

testBackend();
