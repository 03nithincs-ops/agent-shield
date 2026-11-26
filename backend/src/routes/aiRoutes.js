const express = require('express');
const router = express.Router();
const aiController = require('../controllers/aiController');
const { authenticate } = require('../middleware/auth');

router.get('/health', aiController.getHealth);
router.get('/models', aiController.getModels);
router.post('/create-agent', authenticate, aiController.createAgentFromPrompt);

module.exports = router;
