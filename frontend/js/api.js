/* API client for AGENT SHIELD backend */
const API = {
  async request(path, options = {}) {
    const res = await fetch(path, {
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
      ...options,
    });
    const text = await res.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { raw: text };
    }
    if (!res.ok) {
      const msg = (data && (data.detail || data.message)) || `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return data;
  },

  getOverview: () => API.request("/api/dashboard/overview"),
  getTools: () => API.request("/api/tools"),
  getAgents: () => API.request("/api/agents"),
  createAgent: (payload) => API.request("/api/agents", { method: "POST", body: JSON.stringify(payload) }),
  setAgentStatus: (id, status) =>
    API.request(`/api/agents/${encodeURIComponent(id)}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
  rotateAgentKey: (id) =>
    API.request(`/api/agents/${encodeURIComponent(id)}/rotate-key`, { method: "POST" }),

  getPermissions: () => API.request("/api/permissions"),
  upsertPermission: (payload) =>
    API.request("/api/permissions", { method: "POST", body: JSON.stringify(payload) }),
  revokePermission: (id) =>
    API.request(`/api/permissions/${encodeURIComponent(id)}`, { method: "DELETE" }),

  getBehaviourSummary: () => API.request("/api/behaviour/summary"),
  getBehaviourActivity: () => API.request("/api/behaviour/activity?limit=60"),

  getAlerts: () => API.request("/api/alerts?limit=100"),
  ackAlert: (id) => API.request(`/api/alerts/${encodeURIComponent(id)}/acknowledge`, { method: "POST" }),

  getApprovals: () => API.request("/api/approvals"),
  approveRequest: (id, notes = "Approved via dashboard") =>
    API.request(`/api/approvals/${encodeURIComponent(id)}/approve`, {
      method: "POST",
      body: JSON.stringify({ reviewer: "admin", notes }),
    }),
  rejectRequest: (id, notes = "Rejected via dashboard") =>
    API.request(`/api/approvals/${encodeURIComponent(id)}/reject`, {
      method: "POST",
      body: JSON.stringify({ reviewer: "admin", notes }),
    }),

  getAuditLogs: (decision = "") => {
    const q = decision ? `?limit=120&decision=${encodeURIComponent(decision)}` : "?limit=120";
    return API.request(`/api/audit/logs${q}`);
  },
  verifyAuditChain: () => API.request("/api/audit/verify"),

  getScenarios: () => API.request("/api/playground/scenarios"),
  getDemoKeys: () => API.request("/api/playground/demo-keys"),
  runScenario: (scenarioId) =>
    API.request("/api/playground/run", {
      method: "POST",
      body: JSON.stringify({ scenario_id: scenarioId, params: {} }),
    }),
  executeGateway: (apiKey, payload) =>
    API.request("/api/gateway/execute", {
      method: "POST",
      headers: apiKey ? { "X-Agent-Key": apiKey } : {},
      body: JSON.stringify(payload),
    }),

  resetDemo: () => API.request("/api/admin/reset-demo", { method: "POST" }),
};
