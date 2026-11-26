const ollamaService = require('../services/ollamaService');
const Agent = require('../models/Agent');

exports.getHealth = async (req, res, next) => {
  try {
    const conn = await ollamaService.checkConnection();
    const modelStatus = await ollamaService.checkModelAvailability();

    res.json({
      success: true,
      ollama: {
        reachable: conn.reachable,
        endpoint: conn.endpoint,
        error: conn.error || null
      },
      model: {
        configuredModel: ollamaService.model,
        available: modelStatus.available,
        reason: modelStatus.reason,
        installedModels: modelStatus.installedModels || []
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.getModels = async (req, res, next) => {
  try {
    const modelStatus = await ollamaService.checkModelAvailability();
    res.json({
      success: true,
      configuredModel: ollamaService.model,
      available: modelStatus.available,
      installedModels: modelStatus.installedModels,
      details: modelStatus.reason
    });
  } catch (error) {
    next(error);
  }
};

exports.createAgentFromPrompt = async (req, res, next) => {
  try {
    const { prompt, saveDraft = false } = req.body;
    if (!prompt || typeof prompt !== 'string' || prompt.trim().length < 5) {
      return res.status(400).json({
        success: false,
        error: 'Please provide a valid natural-language description of the desired agent (at least 5 characters).'
      });
    }

    console.log(`[AI Controller] Generating agent blueprint from user prompt: "${prompt.slice(0, 80)}..."`);
    
    // Call Ollama with Qwen3
    const result = await ollamaService.generateAgentBlueprint(prompt);
    const blueprint = result.blueprint;

    let savedAgent = null;
    if (saveDraft) {
      const agentId = 'agt_' + Math.random().toString(36).slice(2, 6);
      savedAgent = new Agent({
        agentId,
        name: blueprint.name,
        description: blueprint.description,
        objective: blueprint.objective,
        instructions: blueprint.instructions,
        model: blueprint.model,
        status: 'pending_approval',
        riskLevel: blueprint.riskLevel,
        allowedTools: blueprint.allowedTools,
        permissions: blueprint.permissions,
        safetyRestrictions: blueprint.safetyRestrictions,
        executionSettings: blueprint.executionSettings,
        createdBy: req.user ? req.user.email : 'system'
      });
      await savedAgent.save();
    }

    res.json({
      success: true,
      message: 'Agent blueprint generated and validated successfully by local LLM.',
      modelUsed: result.modelUsed,
      blueprint,
      savedDraft: savedAgent ? {
        id: savedAgent.agentId,
        status: savedAgent.status
      } : null,
      requiresHumanApproval: true
    });
  } catch (error) {
    if (error.message.startsWith('LLM_OFFLINE') || error.message.startsWith('LLM_MODEL_MISSING')) {
      return res.status(503).json({
        success: false,
        error: error.message,
        help: 'To use local AI agent generation, start Ollama locally (`ollama serve`) and pull Qwen3 (`ollama pull qwen3`).'
      });
    }
    next(error);
  }
};
