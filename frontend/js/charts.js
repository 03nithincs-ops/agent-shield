/* Chart.js dashboard visualizations for AGENT SHIELD */
const ShieldCharts = {
  decisionChart: null,
  riskChart: null,

  renderOverviewCharts(overview) {
    if (typeof Chart === "undefined") return;

    const counts = overview.decision_counts || {};
    const decCtx = document.getElementById("chart-decisions");
    if (decCtx) {
      if (this.decisionChart) this.decisionChart.destroy();
      this.decisionChart = new Chart(decCtx, {
        type: "doughnut",
        data: {
          labels: ["ALLOW", "BLOCK", "MONITOR", "REQUIRE_APPROVAL"],
          datasets: [
            {
              data: [
                counts.ALLOW || 0,
                counts.BLOCK || 0,
                counts.MONITOR || 0,
                counts.REQUIRE_APPROVAL || 0,
              ],
              backgroundColor: ["#10b981", "#ef4444", "#f59e0b", "#06b6d4"],
              borderColor: "#111c33",
              borderWidth: 2,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: "bottom",
              labels: { color: "#cbd5e1", padding: 14 },
            },
          },
        },
      });
    }

    const riskCtx = document.getElementById("chart-risk");
    const series = overview.recent_risk_series || [];
    if (riskCtx) {
      if (this.riskChart) this.riskChart.destroy();
      const colors = series.map((s) => {
        if (s.decision === "BLOCK") return "#ef4444";
        if (s.decision === "ALLOW") return "#10b981";
        return "#f59e0b";
      });
      this.riskChart = new Chart(riskCtx, {
        type: "bar",
        data: {
          labels: series.length ? series.map((s) => s.label) : ["No events yet"],
          datasets: [
            {
              label: "Risk Score (0-100)",
              data: series.length ? series.map((s) => s.risk_score) : [0],
              backgroundColor: series.length ? colors : ["#1e2f52"],
              borderRadius: 5,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              min: 0,
              max: 100,
              ticks: { color: "#94a3b8" },
              grid: { color: "rgba(148,163,184,0.1)" },
            },
            x: {
              ticks: { color: "#94a3b8", maxRotation: 35, minRotation: 0 },
              grid: { display: false },
            },
          },
          plugins: {
            legend: { display: false },
          },
        },
      });
    }
  },
};
