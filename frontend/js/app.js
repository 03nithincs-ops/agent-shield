/* AGENT SHIELD — 8-Page Interactive Cybersecurity Dashboard Controller */
(() => {
  const PAGE_META = {
    overview: ["Overview Dashboard", "Real-time runtime authorization, Isolation Forest baseline monitoring, and tamper-evident audit telemetry."],
    creator: ["Agent Creator", "Register new deterministic Python-managed agents with SHA-256 credentials and trusted baselines."],
    agents: ["Agent Management", "Manage active/inactive agent status, tool bindings, and key rotation."],
    permissions: ["Permission Registry", "Assign or revoke live least-privilege rules (takes effect immediately; ML never overrides DENY)."],
    behaviour: ["Behaviour Monitor", "Per-agent trusted normal baselines, Isolation Forest anomaly detection, and 5-feature sliding-window tracking."],
    alerts: ["Security Alerts & Approvals", "Review pending sensitive requests (with live revalidation) and flagged alerts."],
    audit: ["Audit Logs", "Tamper-evident SHA-256 hash-chained log of every intercepted request."],
    playground: ["Security Playground", "Execute all 9 live security scenarios or custom requests with full 8-step pipeline trace."],
  };

  let currentPage = "overview";
  let cachedTools = [];
  let cachedDemoKeys = {};

  function esc(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function showToast(msg, isError = false) {
    const el = document.getElementById("global-toast");
    el.textContent = msg;
    el.style.borderColor = isError ? "#ef4444" : "#06b6d4";
    el.classList.remove("hidden");
    clearTimeout(window.__toastTimer);
    window.__toastTimer = setTimeout(() => el.classList.add("hidden"), 4000);
  }

  function decisionBadge(decision) {
    const d = (decision || "").toUpperCase();
    if (d === "ALLOW" || d === "EXECUTED" || d === "ACTIVE") return `<span class="badge badge-allow">${esc(d)}</span>`;
    if (d === "BLOCK" || d === "REJECTED" || d === "INACTIVE" || d === "BLOCKED_ON_REVALIDATION") {
      return `<span class="badge badge-block">${esc(d)}</span>`;
    }
    return `<span class="badge badge-amber">${esc(d || "UNKNOWN")}</span>`;
  }

  function severityBadge(sev) {
    const s = (sev || "").toUpperCase();
    if (s === "CRITICAL" || s === "HIGH") return `<span class="badge badge-block">${esc(s)}</span>`;
    if (s === "MEDIUM") return `<span class="badge badge-amber">${esc(s)}</span>`;
    return `<span class="badge badge-allow">${esc(s)}</span>`;
  }

  function fmtTime(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso;
    }
  }

  function renderPipelineTrace(payload) {
    const container = document.getElementById("playground-trace");
    if (!container) return;
    const step = payload && payload.steps && payload.steps.length ? payload.steps[payload.steps.length - 1] : payload;
    if (!step || !step.pipeline_trace) {
      container.innerHTML = `<div class="meta-tile"><strong>Complete</strong><span>Inspect detailed output below.</span></div>`;
      return;
    }
    const bd = step.risk_breakdown || {};
    const tiles = step.pipeline_trace
      .map(
        (t) => `
      <div class="meta-tile">
        <strong>${esc(t.outcome)}</strong>
        <span>${esc(t.stage)}</span>
        <div class="muted" style="margin-top:4px;font-size:0.72rem;">${esc(t.detail)}</div>
      </div>`
      )
      .join("");
    const riskSummary = `
      <div class="meta-tile" style="grid-column: 1 / -1;">
        <strong>Explainable Risk Index: ${esc(step.risk_score)}/100 (${esc(step.risk_level)})</strong>
        <span>Sensitivity: +${bd.resource_action_sensitivity || 0} | Policy/Injection: +${bd.policy_and_injection || 0} | Behaviour Rules: +${bd.behaviour_rules || 0} | Isolation Forest ML: +${bd.ml_isolation_forest || 0}</span>
        <div class="muted" style="margin-top:4px;font-size:0.74rem;">${esc(step.risk_disclaimer || "")}</div>
      </div>`;
    container.innerHTML = tiles + riskSummary;
  }

  // ---- Navigation ----
  function switchPage(page) {
    currentPage = page;
    document.querySelectorAll(".nav-item").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.page === page);
    });
    document.querySelectorAll(".page").forEach((sec) => {
      sec.classList.toggle("active", sec.id === `page-${page}`);
    });
    const [title, sub] = PAGE_META[page] || ["AGENT SHIELD", ""];
    document.getElementById("page-title").textContent = title;
    document.getElementById("page-subtitle").textContent = sub;
    loadCurrentPage();
  }

  async function loadCurrentPage() {
    try {
      await refreshHeaderBadges();
      if (currentPage === "overview") await loadOverview();
      else if (currentPage === "creator") await loadCreator();
      else if (currentPage === "agents") await loadAgents();
      else if (currentPage === "permissions") await loadPermissions();
      else if (currentPage === "behaviour") await loadBehaviour();
      else if (currentPage === "alerts") await loadAlertsAndApprovals();
      else if (currentPage === "audit") await loadAuditLogs();
      else if (currentPage === "playground") await loadPlayground();
    } catch (err) {
      showToast(`Error loading ${currentPage}: ${err.message}`, true);
    }
  }

  async function refreshHeaderBadges() {
    try {
      const ov = await API.getOverview();
      document.getElementById("nav-alert-count").textContent = ov.open_alerts + ov.pending_approvals;
      const pill = document.getElementById("chain-pill");
      if (ov.audit_chain_valid) {
        pill.className = "badge badge-allow";
        pill.textContent = `SHA-256 Chain: VALID (${ov.audit_total_records})`;
      } else {
        pill.className = "badge badge-block";
        pill.textContent = `SHA-256 Chain: TAMPER DETECTED`;
      }
    } catch {
      // non-fatal
    }
  }

  // ---- PAGE 1: OVERVIEW ----
  async function loadOverview() {
    const ov = await API.getOverview();
    document.getElementById("kpi-agents").textContent = `${ov.active_agents} / ${ov.total_agents}`;
    document.getElementById("kpi-agents-meta").textContent = "Active / total registered";
    document.getElementById("kpi-requests").textContent = ov.total_requests;
    document.getElementById("kpi-allow").textContent = ov.decision_counts.ALLOW || 0;
    document.getElementById("kpi-block").textContent = ov.decision_counts.BLOCK || 0;
    const amber = (ov.decision_counts.MONITOR || 0) + (ov.decision_counts.REQUIRE_APPROVAL || 0);
    document.getElementById("kpi-amber").textContent = amber;
    document.getElementById("kpi-amber-meta").textContent = `${ov.pending_approvals} pending approval(s)`;
    document.getElementById("kpi-risk").textContent = ov.avg_risk_score;

    ShieldCharts.renderOverviewCharts(ov);

    const db = ov.synthetic_db_counts || {};
    const th = ov.thresholds || {};
    document.getElementById("overview-db-meta").innerHTML = `
      <div class="meta-tile"><strong>${db.customers || 0}</strong><span>Synthetic Customers</span></div>
      <div class="meta-tile"><strong>${db.loans || 0}</strong><span>Synthetic Loans</span></div>
      <div class="meta-tile"><strong>${db.payments || 0}</strong><span>Synthetic Payments</span></div>
      <div class="meta-tile"><strong>${db.employees || 0} / ${db.payroll || 0}</strong><span>Employees / Payroll</span></div>
      <div class="meta-tile"><strong>${th.monitor_requests || 6} / ${th.block_requests || 12}</strong><span>Req/60s Monitor / Block</span></div>
      <div class="meta-tile"><strong>$${Number(th.payment_approval_threshold || 5000).toLocaleString()}</strong><span>Payment Approval Threshold</span></div>
    `;
  }

  // ---- PAGE 2: AGENT CREATOR ----
  async function loadCreator() {
    const res = await API.getTools();
    cachedTools = res.tools || [];
    const box = document.getElementById("creator-tools-checkboxes");
    box.innerHTML = cachedTools
      .map(
        (t) => `
      <label class="checkbox-card">
        <input type="checkbox" name="tool" value="${esc(t.name)}" data-resource="${esc(t.resource)}" data-action="${esc(t.action)}" />
        <div>
          <strong>${esc(t.name)}</strong>
          <div class="muted">${esc(t.resource)}:${esc(t.action)} ${t.sensitive ? "(Sensitive)" : ""}</div>
        </div>
      </label>`
      )
      .join("");
  }

  document.getElementById("form-create-agent").addEventListener("submit", async (e) => {
    e.preventDefault();
    const checked = Array.from(document.querySelectorAll('#creator-tools-checkboxes input[type="checkbox"]:checked'));
    const tools = checked.map((c) => c.value);
    const autoPerms = document.getElementById("ag-auto-perms").checked;
    const initialPermissions = autoPerms
      ? checked.map((c) => ({
          resource: c.dataset.resource,
          action: c.dataset.action,
          effect: "ALLOW",
          requires_approval_above: c.dataset.resource === "payments" && c.dataset.action === "execute" ? 5000 : null,
        }))
      : [];

    try {
      const data = await API.createAgent({
        name: document.getElementById("ag-name").value.trim(),
        role: document.getElementById("ag-role").value.trim(),
        description: document.getElementById("ag-desc").value.trim(),
        system_instructions: document.getElementById("ag-inst").value.trim(),
        available_tools: tools,
        initial_permissions: initialPermissions,
      });
      const ag = data.agent;
      const banner = document.getElementById("created-agent-banner");
      banner.classList.remove("hidden");
      banner.innerHTML = `
        <strong>Agent Created &amp; Trusted Baseline Seeded!</strong><br/>
        Agent ID: <code>${esc(ag.agent_id)}</code> &nbsp;|&nbsp;
        API Credential (copy now — stored SHA-256 hashed): <code>${esc(ag.api_key)}</code>
      `;
      e.target.reset();
      showToast(`Created agent ${ag.name}`);
      refreshHeaderBadges();
    } catch (err) {
      showToast(`Failed to create agent: ${err.message}`, true);
    }
  });

  // ---- PAGE 3: AGENT MANAGEMENT ----
  async function loadAgents() {
    const res = await API.getAgents();
    const agents = res.agents || [];
    const tbody = document.getElementById("agents-tbody");
    if (!agents.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-cell">No agents registered yet.</td></tr>`;
      return;
    }
    tbody.innerHTML = agents
      .map((a) => {
        const nextStatus = a.status === "active" ? "inactive" : "active";
        const permsHtml = (a.permissions || [])
          .map((p) => `<span class="badge ${p.effect === "ALLOW" ? "badge-cyan" : "badge-block"}">${esc(p.resource)}:${esc(p.action)}</span>`)
          .join(" ");
        return `
        <tr>
          <td><code>${esc(a.agent_id)}</code></td>
          <td><strong>${esc(a.name)}</strong><div class="muted">${esc(a.role)}</div></td>
          <td>${decisionBadge(a.status)}</td>
          <td><code>${esc(a.credential_prefix)}</code></td>
          <td>${(a.available_tools || []).map((t) => `<code>${esc(t)}</code>`).join("<br/>") || "—"}</td>
          <td>${permsHtml || '<span class="muted">None</span>'}</td>
          <td class="inline-actions">
            <button class="btn btn-outline btn-sm" data-toggle-agent="${esc(a.agent_id)}" data-next="${nextStatus}">
              Set ${nextStatus}
            </button>
            <button class="btn btn-outline btn-sm" data-rotate-agent="${esc(a.agent_id)}">Rotate Key</button>
          </td>
        </tr>`;
      })
      .join("");

    tbody.querySelectorAll("[data-toggle-agent]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await API.setAgentStatus(btn.dataset.toggleAgent, btn.dataset.next);
          showToast(`Agent ${btn.dataset.toggleAgent} set to ${btn.dataset.next}`);
          loadAgents();
        } catch (err) {
          showToast(err.message, true);
        }
      });
    });

    tbody.querySelectorAll("[data-rotate-agent]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          const data = await API.rotateAgentKey(btn.dataset.rotateAgent);
          showToast(`New key for ${data.agent.name}: ${data.agent.api_key}`);
          loadAgents();
        } catch (err) {
          showToast(err.message, true);
        }
      });
    });
  }

  // ---- PAGE 4: PERMISSION REGISTRY ----
  async function loadPermissions() {
    const [agRes, permRes] = await Promise.all([API.getAgents(), API.getPermissions()]);
    const agents = agRes.agents || [];
    const sel = document.getElementById("perm-agent");
    sel.innerHTML = agents.map((a) => `<option value="${esc(a.agent_id)}">${esc(a.name)} (${esc(a.agent_id)})</option>`).join("");

    const perms = permRes.permissions || [];
    const tbody = document.getElementById("permissions-tbody");
    if (!perms.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-cell">No policy rules configured.</td></tr>`;
      return;
    }
    tbody.innerHTML = perms
      .map(
        (p) => `
      <tr>
        <td><strong>${esc(p.agent_name)}</strong><div class="muted">${esc(p.agent_id)}</div></td>
        <td><code>${esc(p.resource)}</code></td>
        <td><code>${esc(p.action)}</code></td>
        <td>${decisionBadge(p.effect)}</td>
        <td>${p.requires_approval_above != null ? "$" + Number(p.requires_approval_above).toLocaleString() : "—"}</td>
        <td>${p.max_amount != null ? "$" + Number(p.max_amount).toLocaleString() : "—"}</td>
        <td>
          <button class="btn btn-block btn-sm" data-revoke="${esc(p.permission_id)}">Revoke Now</button>
        </td>
      </tr>`
      )
      .join("");

    tbody.querySelectorAll("[data-revoke]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await API.revokePermission(btn.dataset.revoke);
          showToast("Permission revoked immediately.");
          loadPermissions();
        } catch (err) {
          showToast(err.message, true);
        }
      });
    });
  }

  document.getElementById("form-permission").addEventListener("submit", async (e) => {
    e.preventDefault();
    const apprVal = document.getElementById("perm-approval-above").value;
    try {
      await API.upsertPermission({
        agent_id: document.getElementById("perm-agent").value,
        resource: document.getElementById("perm-resource").value,
        action: document.getElementById("perm-action").value,
        effect: document.getElementById("perm-effect").value,
        requires_approval_above: apprVal ? Number(apprVal) : null,
      });
      showToast("Policy rule saved.");
      loadPermissions();
    } catch (err) {
      showToast(err.message, true);
    }
  });

  // ---- PAGE 5: BEHAVIOUR MONITOR ----
  async function loadBehaviour() {
    const [sumRes, actRes] = await Promise.all([API.getBehaviourSummary(), API.getBehaviourActivity()]);
    const agents = sumRes.agents || [];
    if (agents.length) {
      document.getElementById("behaviour-detector-mode").textContent = `Active Detector: ${agents[0].detector_mode}`;
    }
    const tbody = document.getElementById("behaviour-tbody");
    tbody.innerHTML = agents.length
      ? agents
          .map((a) => {
            const b = a.baseline || {};
            return `
        <tr>
          <td><strong>${esc(a.agent_name)}</strong><div class="muted">${esc(a.role)}</div></td>
          <td>
            <code>${esc((b.normal_resources || []).join(", "))}</code>
            <div class="muted">${esc(b.normal_hours_utc || "08:00-20:00")} UTC | ${b.sample_count || 250} trusted samples</div>
          </td>
          <td>${a.recent_requests}</td>
          <td>${a.unique_records_accessed}</td>
          <td>${a.failed_authz_attempts}</td>
          <td><span class="badge badge-block">${a.blocked_count}</span> / <span class="badge badge-amber">${a.monitored_count}</span></td>
          <td>${a.avg_risk_score} / <strong>${a.max_risk_score}</strong></td>
          <td>${(a.resources_touched || []).map((r) => `<code>${esc(r)}</code>`).join(" ") || "—"}</td>
        </tr>`;
          })
          .join("")
      : `<tr><td colspan="8" class="empty-cell">No agents found.</td></tr>`;

    const acts = actRes.activity || [];
    const atbody = document.getElementById("activity-tbody");
    atbody.innerHTML = acts.length
      ? acts
          .map(
            (x) => `
        <tr>
          <td>${fmtTime(x.timestamp)}</td>
          <td>${esc(x.agent_name || x.agent_id)}</td>
          <td><code>${esc(x.tool_name)}</code></td>
          <td><code>${esc(x.resource)}:${esc(x.action)}</code></td>
          <td>${x.record_count}</td>
          <td>${decisionBadge(x.decision)}</td>
          <td>${x.risk_score}</td>
        </tr>`
          )
          .join("")
      : `<tr><td colspan="7" class="empty-cell">No activity recorded yet. Run a scenario in Security Playground.</td></tr>`;
  }

  // ---- PAGE 6: SECURITY ALERTS & APPROVALS ----
  async function loadAlertsAndApprovals() {
    const [apprRes, alertRes] = await Promise.all([API.getApprovals(), API.getAlerts()]);
    const approvals = apprRes.approvals || [];
    const ptbody = document.getElementById("approvals-tbody");
    ptbody.innerHTML = approvals.length
      ? approvals
          .map(
            (r) => `
        <tr>
          <td><code>${esc(r.approval_id)}</code></td>
          <td><strong>${esc(r.agent_name)}</strong><div class="muted">${esc(r.agent_id)}</div></td>
          <td><code>${esc(r.tool_name)}</code><div class="muted mono">${esc(JSON.stringify(r.arguments))}</div></td>
          <td>${r.risk_score}</td>
          <td>${decisionBadge(r.status)}</td>
          <td>${esc(r.reason)}</td>
          <td class="inline-actions">
            ${
              r.status === "PENDING"
                ? `<button class="btn btn-allow btn-sm" data-approve="${esc(r.approval_id)}">Approve</button>
                   <button class="btn btn-block btn-sm" data-reject="${esc(r.approval_id)}">Reject</button>`
                : `<span class="muted">${esc(r.reviewed_by || "Reviewed")}</span>`
            }
          </td>
        </tr>`
          )
          .join("")
      : `<tr><td colspan="7" class="empty-cell">No approval requests yet. Trigger Scenario 5 in Security Playground.</td></tr>`;

    ptbody.querySelectorAll("[data-approve]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          const res = await API.approveRequest(btn.dataset.approve);
          showToast(`Approval ${res.approval_id}: ${res.status}`);
          loadAlertsAndApprovals();
          refreshHeaderBadges();
        } catch (err) {
          showToast(err.message, true);
        }
      });
    });

    ptbody.querySelectorAll("[data-reject]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          const res = await API.rejectRequest(btn.dataset.reject);
          showToast(`Approval ${res.approval_id}: ${res.status}`);
          loadAlertsAndApprovals();
          refreshHeaderBadges();
        } catch (err) {
          showToast(err.message, true);
        }
      });
    });

    const alerts = alertRes.alerts || [];
    const atbody = document.getElementById("alerts-tbody");
    atbody.innerHTML = alerts.length
      ? alerts
          .map(
            (a) => `
        <tr>
          <td>${fmtTime(a.created_at)}</td>
          <td>${severityBadge(a.severity)}</td>
          <td><code>${esc(a.category)}</code></td>
          <td>${esc(a.agent_name)}</td>
          <td>${decisionBadge(a.decision)}</td>
          <td>${(a.reasons || []).map((r) => `<div>• ${esc(r)}</div>`).join("")}</td>
          <td>
            ${
              a.acknowledged
                ? '<span class="badge badge-muted">Ack</span>'
                : `<button class="btn btn-outline btn-sm" data-ack="${esc(a.alert_id)}">Ack</button>`
            }
          </td>
        </tr>`
          )
          .join("")
      : `<tr><td colspan="7" class="empty-cell">No security alerts yet.</td></tr>`;

    atbody.querySelectorAll("[data-ack]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await API.ackAlert(btn.dataset.ack);
          loadAlertsAndApprovals();
          refreshHeaderBadges();
        } catch (err) {
          showToast(err.message, true);
        }
      });
    });
  }

  // ---- PAGE 7: AUDIT LOGS ----
  async function loadAuditLogs() {
    const decision = document.getElementById("audit-filter-decision").value;
    const res = await API.getAuditLogs(decision);
    renderChainBanner(res.chain);
    const logs = res.logs || [];
    const tbody = document.getElementById("audit-tbody");
    tbody.innerHTML = logs.length
      ? logs
          .map(
            (l) => `
        <tr>
          <td><code>${esc(l.event_id)}</code></td>
          <td>${fmtTime(l.timestamp)}</td>
          <td><strong>${esc(l.agent_name)}</strong><div class="muted">${esc(l.authenticated_agent)}</div></td>
          <td><code>${esc(l.requested_resource)}:${esc(l.requested_action)}</code></td>
          <td>${esc(l.auth_result)}</td>
          <td>${esc(l.policy_result)}</td>
          <td>${decisionBadge(l.final_decision)}</td>
          <td>${esc(l.execution_result)}</td>
          <td class="mono" title="${esc(l.current_hash)}">${esc((l.current_hash || "").slice(0, 14))}…</td>
        </tr>`
          )
          .join("")
      : `<tr><td colspan="9" class="empty-cell">No audit logs recorded yet.</td></tr>`;
  }

  function renderChainBanner(chain) {
    const el = document.getElementById("audit-chain-banner");
    if (!chain) return;
    if (chain.valid) {
      el.className = "callout callout-allow";
      el.innerHTML = `<strong>Cryptographic Integrity Verified:</strong> All ${chain.total_records} audit record(s) match the SHA-256 hash chain. Latest hash: <code>${esc((chain.latest_hash || "").slice(0, 24))}…</code>`;
    } else {
      el.className = "callout callout-block";
      el.innerHTML = `<strong>TAMPERING DETECTED:</strong> ${chain.broken_count} broken hash link(s) out of ${chain.total_records} audit record(s)!`;
    }
  }

  document.getElementById("audit-filter-decision").addEventListener("change", loadAuditLogs);
  document.getElementById("btn-verify-chain").addEventListener("click", async () => {
    try {
      const chain = await API.verifyAuditChain();
      renderChainBanner(chain);
      showToast(chain.valid ? "SHA-256 audit chain verified intact." : "Audit chain tampering detected!", !chain.valid);
      refreshHeaderBadges();
    } catch (err) {
      showToast(err.message, true);
    }
  });

  // ---- PAGE 8: SECURITY PLAYGROUND ----
  async function loadPlayground() {
    const [scRes, keyRes, toolRes] = await Promise.all([API.getScenarios(), API.getDemoKeys(), API.getTools()]);
    cachedDemoKeys = keyRes.demo_keys || {};
    cachedTools = toolRes.tools || [];

    const grid = document.getElementById("scenarios-grid");
    grid.innerHTML = (scRes.scenarios || [])
      .map(
        (s) => `
      <div class="scenario-card">
        <div>
          <div class="inline-actions" style="justify-content:space-between; margin-bottom:6px;">
            <span class="badge badge-cyan">Scenario ${s.scenario_id}</span>
            <span class="badge badge-muted">${esc(s.expected)}</span>
          </div>
          <h4>${esc(s.title)}</h4>
          <p>${esc(s.description)}</p>
        </div>
        <button class="btn btn-cyan btn-sm full-width" data-run-scenario="${s.scenario_id}">
          Run Live Scenario ${s.scenario_id}
        </button>
      </div>`
      )
      .join("");

    grid.querySelectorAll("[data-run-scenario]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const sid = Number(btn.dataset.runScenario);
        const out = document.getElementById("playground-output");
        out.textContent = `Running Scenario ${sid} through live Security Gateway...`;
        try {
          const result = await API.runScenario(sid);
          renderPipelineTrace(result);
          out.textContent = JSON.stringify(result, null, 2);
          showToast(`Scenario ${sid}: ${result.actual_outcome} (${result.passed ? "PASS" : "CHECK"})`, !result.passed);
          refreshHeaderBadges();
        } catch (err) {
          out.textContent = `Error: ${err.message}`;
          showToast(err.message, true);
        }
      });
    });

    const preset = document.getElementById("pg-agent-key-preset");
    preset.innerHTML =
      `<option value="">-- Choose Demo Agent Credential --</option>` +
      Object.entries(cachedDemoKeys)
        .map(([id, key]) => `<option value="${esc(key)}">${esc(id)} (${esc(key.slice(0, 18))}…)</option>`)
        .join("") +
      `<option value="agsh_invalid_test_key">Invalid Forged Key (Fail-Closed Test)</option>`;

    preset.onchange = () => {
      if (preset.value) document.getElementById("pg-agent-key").value = preset.value;
    };

    const toolSel = document.getElementById("pg-tool");
    toolSel.innerHTML = cachedTools
      .map((t) => `<option value="${esc(t.name)}">${esc(t.name)} (${esc(t.resource)}:${esc(t.action)})</option>`)
      .join("");
  }

  document.getElementById("form-custom-gateway").addEventListener("submit", async (e) => {
    e.preventDefault();
    const apiKey = document.getElementById("pg-agent-key").value.trim();
    const toolName = document.getElementById("pg-tool").value;
    const promptContext = document.getElementById("pg-prompt").value.trim() || null;
    const hourVal = document.getElementById("pg-hour").value.trim();
    const simulatedHour = hourVal !== "" ? Number(hourVal) : null;
    let args = {};
    try {
      args = JSON.parse(document.getElementById("pg-args").value || "{}");
    } catch {
      showToast("Arguments must be valid JSON.", true);
      return;
    }

    const out = document.getElementById("playground-output");
    out.textContent = "Sending request to POST /api/gateway/execute...";
    try {
      const result = await API.executeGateway(apiKey, {
        tool_name: toolName,
        arguments: args,
        prompt_context: promptContext,
        simulated_hour: simulatedHour,
      });
      renderPipelineTrace(result);
      out.textContent = JSON.stringify(result, null, 2);
      showToast(`Gateway Decision: ${result.decision}`);
      refreshHeaderBadges();
    } catch (err) {
      out.textContent = `Error: ${err.message}`;
      showToast(err.message, true);
    }
  });

  // ---- Global Controls ----
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => switchPage(btn.dataset.page));
  });

  document.getElementById("btn-refresh").addEventListener("click", loadCurrentPage);

  document.getElementById("btn-reset-demo").addEventListener("click", async () => {
    try {
      await API.resetDemo();
      showToast("Synthetic demo database reset cleanly.");
      loadCurrentPage();
    } catch (err) {
      showToast(err.message, true);
    }
  });

  // Initial load
  loadCurrentPage();
})();
