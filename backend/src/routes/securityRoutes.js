const express = require('express');
const router = express.Router();
const securityController = require('../controllers/securityController');
const { authenticate, authorize } = require('../middleware/auth');

router.get('/alerts', authenticate, securityController.getAlerts);
router.post('/alerts/:id/acknowledge', authenticate, authorize('ADMIN', 'ANALYST'), securityController.acknowledgeAlert);
router.post('/alerts/:id/resolve', authenticate, authorize('ADMIN', 'ANALYST'), securityController.resolveAlert);

router.get('/anomalies', authenticate, securityController.getAnomalies);
router.get('/audit-logs', authenticate, securityController.getAuditLogs);
router.get('/audit-logs/verify', authenticate, securityController.verifyAuditLogs);
router.get('/metrics', authenticate, securityController.getSecurityMetrics);
router.post('/analyze', authenticate, securityController.analyzeActivity);
router.post('/freeze', authenticate, authorize('ADMIN'), securityController.toggleFreeze);

module.exports = router;
