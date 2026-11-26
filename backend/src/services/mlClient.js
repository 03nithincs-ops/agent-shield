const axios = require('axios');
const { ML_SERVICE_URL } = require('../config/env');

class MLClient {
  constructor() {
    this.baseURL = ML_SERVICE_URL.replace(/\/+$/, '');
    this.timeout = 5000;
  }

  /**
   * Check ML service health
   */
  async checkHealth() {
    try {
      const res = await axios.get(`${this.baseURL}/health`, { timeout: 2000 });
      return {
        online: true,
        endpoint: this.baseURL,
        data: res.data
      };
    } catch (error) {
      return {
        online: false,
        endpoint: this.baseURL,
        error: error.message
      };
    }
  }

  /**
   * Retrieve model info and parameters
   */
  async getModelInfo() {
    try {
      const res = await axios.get(`${this.baseURL}/model-info`, { timeout: 2500 });
      return res.data;
    } catch (error) {
      return {
        available: false,
        error: `ML Service unreachable at ${this.baseURL}: ${error.message}`
      };
    }
  }

  /**
   * Send single activity feature vector to Isolation Forest model for anomaly prediction
   */
  async predict(features) {
    try {
      const res = await axios.post(`${this.baseURL}/predict`, features, { timeout: this.timeout });
      return {
        success: true,
        isAnomaly: res.data.is_anomaly,
        anomalyScore: res.data.anomaly_score,
        prediction: res.data.prediction,
        explanation: res.data.explanation,
        raw: res.data
      };
    } catch (error) {
      console.warn(`[ML Client] Prediction request failed: ${error.message}. Returning fallback baseline.`);
      return {
        success: false,
        isAnomaly: false,
        anomalyScore: 0.15,
        prediction: 1,
        explanation: `ML service offline (${error.message}). Defaulted to rule-based evaluation.`,
        error: error.message
      };
    }
  }

  /**
   * Trigger model retraining on updated agent activity dataset
   */
  async retrain(trainingData = null) {
    try {
      const res = await axios.post(`${this.baseURL}/train`, trainingData || {}, { timeout: 30000 });
      return {
        success: true,
        data: res.data
      };
    } catch (error) {
      throw new Error(`Failed to retrain ML model: ${error.message}`);
    }
  }
}

module.exports = new MLClient();
