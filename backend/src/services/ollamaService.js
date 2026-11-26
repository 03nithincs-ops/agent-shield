const axios = require('axios');
const { OLLAMA_BASE_URL, OLLAMA_MODEL } = require('../config/env');
const { agentBlueprintSchema, VALID_TOOLS } = require('../validators/agentSchemas');

class OllamaService {
  constructor() {
    this.baseURL = OLLAMA_BASE_URL.replace(/\/+$/, '');
    this.model = OLLAMA_MODEL;
    this.timeout = 45000; // 45 seconds for local LLM inference
  }

  /**
   * Check if Ollama service is reachable
   */
  async checkConnection() {
    try {
      const response = await axios.get(`${this.baseURL}/api/tags`, { timeout: 3000 });
      return {
        reachable: true,
        endpoint: this.baseURL,
        status: response.status
      };
    } catch (error) {
      return {
        reachable: false,
        endpoint: this.baseURL,
        error: error.code === 'ECONNREFUSED' 
          ? `Ollama service is not running on ${this.baseURL}. Please ensure Ollama is installed and started.`
          : error.message
      };
    }
  }

  /**
   * Check if configured model (e.g. qwen3) is available
   */
  async checkModelAvailability() {
    const conn = await this.checkConnection();
    if (!conn.reachable) {
      return {
        available: false,
        model: this.model,
        reason: conn.error,
        installedModels: []
      };
    }

    try {
      const response = await axios.get(`${this.baseURL}/api/tags`, { timeout: 3000 });
      const models = response.data.models || [];
      const installedModels = models.map(m => m.name);
      
      const isAvailable = installedModels.some(m => 
        m.toLowerCase().startsWith(this.model.toLowerCase()) || 
        m.toLowerCase().includes(this.model.toLowerCase())
      );

      return {
        available: isAvailable,
        model: this.model,
        installedModels,
        reason: isAvailable ? 'Model is installed and ready' : `Model '${this.model}' is not in local Ollama library. Available models: [${installedModels.join(', ')}]. Run 'ollama pull ${this.model}' to install.`
      };
    } catch (error) {
      return {
        available: false,
        model: this.model,
        reason: `Failed to query Ollama models: ${error.message}`,
        installedModels: []
      };
    }
  }

  /**
   * Generate an AI Agent Blueprint from natural language requirements using Qwen3
   */
  async generateAgentBlueprint(userPrompt) {
    // 1. Verify connection
    const conn = await this.checkConnection();
    if (!conn.reachable) {
      throw new Error(`LLM_OFFLINE: ${conn.error}`);
    }

    // 2. Verify model availability
    const modelCheck = await this.checkModelAvailability();
    let targetModel = this.model;
    if (!modelCheck.available) {
      if (modelCheck.installedModels.length > 0) {
        // Fall back to first available installed model if exact Qwen3 tag differs
        targetModel = modelCheck.installedModels[0];
        console.warn(`[Ollama] Configured model '${this.model}' not found, utilizing available model '${targetModel}'`);
      } else {
        throw new Error(`LLM_MODEL_MISSING: ${modelCheck.reason}`);
      }
    }

    // 3. Construct structured system prompt
    const systemPrompt = `You are an expert AI Agent Architect and Cybersecurity Engineer.
Your task is to analyze user requirements and generate a strictly valid JSON blueprint for an AI Agent.

Registered Tools available to the agent (allowedTools must ONLY be a subset of these):
${JSON.stringify(VALID_TOOLS, null, 2)}

Valid Permissions:
- READ: Read security logs and file datasets (standard)
- WRITE: Write reports and temporary files (moderate risk)
- DELETE: Delete resources (HIGH risk, destructive)
- UPDATE: Update configurations and records (moderate risk)
- API: Outbound API communications (moderate risk)
- CUSTOMER_DATA: Access sensitive customer records/PII (HIGH risk)
- PAYMENT: Issue or modify payment records (CRITICAL risk)

Rules:
1. Do NOT grant unnecessary permissions. Enforce strict LEAST PRIVILEGE.
2. Return ONLY a pure JSON object. No Markdown code fences, no explanations, no preamble.
3. The JSON structure MUST match this exact schema:
{
  "name": "string (2-64 chars)",
  "description": "string (5-500 chars)",
  "objective": "string (5-500 chars)",
  "instructions": "detailed instructions for the agent runtime",
  "model": "${targetModel}",
  "allowedTools": ["tool_names_from_registered_list"],
  "permissions": {
    "READ": boolean,
    "WRITE": boolean,
    "DELETE": boolean,
    "UPDATE": boolean,
    "API": boolean,
    "CUSTOMER_DATA": boolean,
    "PAYMENT": boolean
  },
  "riskLevel": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "executionSettings": {
    "maxExecutionTimeMs": 30000,
    "maxRequestsPerMin": 15,
    "requireHumanApprovalForSensitive": true
  },
  "safetyRestrictions": [
    "restriction 1",
    "restriction 2"
  ]
}`;

    // 4. Send request to Ollama
    console.log(`[Ollama] Sending prompt to local model '${targetModel}' at ${this.baseURL}/api/chat...`);
    try {
      const response = await axios.post(`${this.baseURL}/api/chat`, {
        model: targetModel,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: `Create an AI agent with these requirements:\n\n${userPrompt}` }
        ],
        stream: false,
        options: {
          temperature: 0.2
        }
      }, {
        timeout: this.timeout
      });

      const rawContent = response.data?.message?.content;
      if (!rawContent) {
        throw new Error('Ollama returned an empty response message.');
      }

      // 5. Clean and parse JSON
      let cleaned = rawContent.trim();
      if (cleaned.startsWith('```json')) {
        cleaned = cleaned.replace(/^```json\s*/, '').replace(/\s*```$/, '');
      } else if (cleaned.startsWith('```')) {
        cleaned = cleaned.replace(/^```\s*/, '').replace(/\s*```$/, '');
      }

      let parsed;
      try {
        parsed = JSON.parse(cleaned);
      } catch (parseErr) {
        throw new Error(`LLM response could not be parsed as JSON: ${parseErr.message}\nRaw response:\n${rawContent}`);
      }

      // 6. Validate with Zod
      const validatedBlueprint = agentBlueprintSchema.parse(parsed);
      return {
        success: true,
        blueprint: validatedBlueprint,
        modelUsed: targetModel
      };

    } catch (error) {
      if (error.code === 'ECONNABORTED') {
        throw new Error(`Ollama request timed out after ${this.timeout / 1000}s while generating agent.`);
      }
      throw error;
    }
  }
}

module.exports = new OllamaService();
