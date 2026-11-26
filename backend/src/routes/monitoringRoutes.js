const express = require('express');
const router = express.Router();
const monitoringController = require('../controllers/monitoringController');
const { authenticate } = require('../middleware/auth');
const validate = require('../middleware/validate');
const { simulateRequestSchema } = require('../validators/agentSchemas');

router.get('/metrics', authenticate, monitoringController.getMetrics);
router.get('/activity', authenticate, monitoringController.getActivity);
router.post('/simulate', authenticate, validate(simulateRequestSchema), monitoringController.simulate);

module.exports = router;
