const express = require('express');
const router = express.Router();
const agentController = require('../controllers/agentController');
const { authenticate, authorize } = require('../middleware/auth');
const validate = require('../middleware/validate');
const { createAgentSchema, executeTaskSchema } = require('../validators/agentSchemas');

router.get('/', authenticate, agentController.getAgents);
router.get('/:id', authenticate, agentController.getAgentById);
router.post('/', authenticate, validate(createAgentSchema), agentController.createAgent);
router.put('/:id', authenticate, agentController.updateAgent);
router.delete('/:id', authenticate, authorize('ADMIN'), agentController.deleteAgent);

router.post('/:id/approve', authenticate, authorize('ADMIN', 'ANALYST'), agentController.approveAgent);
router.post('/:id/reject', authenticate, authorize('ADMIN', 'ANALYST'), agentController.rejectAgent);
router.post('/:id/start', authenticate, agentController.startAgent);
router.post('/:id/stop', authenticate, agentController.stopAgent);
router.post('/:id/suspend', authenticate, authorize('ADMIN', 'ANALYST'), agentController.suspendAgent);
router.post('/:id/recover', authenticate, authorize('ADMIN'), agentController.recoverAgent);
router.post('/:id/revoke', authenticate, authorize('ADMIN'), agentController.revokeAgent);

router.post('/:id/execute', authenticate, validate(executeTaskSchema), agentController.executeTask);
router.get('/:id/activity', authenticate, agentController.getActivity);
router.get('/:id/history', authenticate, agentController.getHistory);

module.exports = router;
