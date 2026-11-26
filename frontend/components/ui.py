"""
AGENT SHIELD - Shared UI Components
"""
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from frontend.api_client import check_backend_health


# ── Color Palette ──────────────────────────────────────────────────────────
COLORS = {
    "allow": "#00d4aa",
    "deny": "#ff4b6e",
    "normal": "#00d4aa",
    "anomalous": "#ff9f43",
    "low": "#00d4aa",
    "medium": "#ffd32a",
    "high": "#ff9f43",
    "critical": "#ff4b6e",
    "primary": "#1e3a5f",
    "accent": "#00b4d8",
    "bg_dark": "#0a0e1a",
    "bg_card": "#111827",
    "text_light": "#e2e8f0",
    "pass_color": "#00d4aa",
    "fail_color": "#ff4b6e",
}

BADGE_STYLES = {
    "ALLOW": f"background-color: #00d4aa22; color: #00d4aa; border: 1px solid #00d4aa; border-radius: 4px; padding: 2px 8px; font-weight: bold;",
    "DENY": f"background-color: #ff4b6e22; color: #ff4b6e; border: 1px solid #ff4b6e; border-radius: 4px; padding: 2px 8px; font-weight: bold;",
    "NORMAL": f"background-color: #00d4aa22; color: #00d4aa; border: 1px solid #00d4aa; border-radius: 4px; padding: 2px 8px; font-weight: bold;",
    "ANOMALOUS": f"background-color: #ff9f4322; color: #ff9f43; border: 1px solid #ff9f43; border-radius: 4px; padding: 2px 8px; font-weight: bold;",
    "LOW": f"background-color: #00d4aa22; color: #00d4aa; border: 1px solid #00d4aa; border-radius: 4px; padding: 2px 8px; font-weight: bold;",
    "MEDIUM": f"background-color: #ffd32a22; color: #ffd32a; border: 1px solid #ffd32a; border-radius: 4px; padding: 2px 8px; font-weight: bold;",
    "HIGH": f"background-color: #ff9f4322; color: #ff9f43; border: 1px solid #ff9f43; border-radius: 4px; padding: 2px 8px; font-weight: bold;",
    "CRITICAL": f"background-color: #ff4b6e33; color: #ff4b6e; border: 1px solid #ff4b6e; border-radius: 4px; padding: 2px 8px; font-weight: bold; animation: pulse 1s infinite;",
    "ACTIVE": f"background-color: #00d4aa22; color: #00d4aa; border: 1px solid #00d4aa; border-radius: 4px; padding: 2px 8px; font-weight: bold;",
    "INACTIVE": f"background-color: #64748b22; color: #94a3b8; border: 1px solid #64748b; border-radius: 4px; padding: 2px 8px; font-weight: bold;",
    "PASS": f"background-color: #00d4aa22; color: #00d4aa; border: 1px solid #00d4aa; border-radius: 4px; padding: 2px 8px; font-weight: bold;",
    "FAIL": f"background-color: #ff4b6e22; color: #ff4b6e; border: 1px solid #ff4b6e; border-radius: 4px; padding: 2px 8px; font-weight: bold;",
    "ERROR": f"background-color: #ff9f4322; color: #ff9f43; border: 1px solid #ff9f43; border-radius: 4px; padding: 2px 8px; font-weight: bold;",
    "UNAVAILABLE": f"background-color: #64748b22; color: #94a3b8; border: 1px solid #64748b; border-radius: 4px; padding: 2px 8px; font-weight: bold;",
}


def get_global_css() -> str:
    return """
<style>
    /* Global Dark Theme */
    .stApp {
        background-color: #0a0e1a;
        color: #e2e8f0;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #0d1b2e;
        border-right: 1px solid #1e3a5f;
    }
    
    [data-testid="stSidebar"] .stMarkdown {
        color: #e2e8f0;
    }
    
    /* Metric Cards */
    .metric-card {
        background: linear-gradient(135deg, #111827 0%, #1a2535 100%);
        border: 1px solid #1e3a5f;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        margin-bottom: 10px;
        transition: transform 0.2s;
    }
    
    .metric-card:hover {
        transform: translateY(-2px);
        border-color: #00b4d8;
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        line-height: 1.1;
    }
    
    .metric-label {
        font-size: 0.85rem;
        color: #94a3b8;
        margin-top: 4px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    /* Alert Banner */
    .alert-banner {
        background: linear-gradient(135deg, #1f1035 0%, #2d1b4e 100%);
        border: 1px solid #ff4b6e;
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 8px;
    }
    
    /* Section Headers */
    .section-header {
        font-size: 1.2rem;
        font-weight: 600;
        color: #00b4d8;
        border-bottom: 1px solid #1e3a5f;
        padding-bottom: 8px;
        margin-bottom: 16px;
    }
    
    /* Result Cards */
    .result-allow {
        background: linear-gradient(135deg, #002e1f 0%, #003d2a 100%);
        border: 2px solid #00d4aa;
        border-radius: 12px;
        padding: 20px;
    }
    
    .result-deny {
        background: linear-gradient(135deg, #2d0a14 0%, #3d0d1a 100%);
        border: 2px solid #ff4b6e;
        border-radius: 12px;
        padding: 20px;
    }
    
    /* Tables */
    .stDataFrame {
        background-color: #111827;
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #1e3a5f 0%, #00b4d8 100%);
        color: white;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.2s;
    }
    
    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 15px rgba(0, 180, 216, 0.4);
    }
    
    /* Input fields */
    .stSelectbox > div, .stTextInput > div {
        background-color: #1a2535;
        border-color: #1e3a5f;
    }
    
    /* Page title */
    .page-title {
        font-size: 2rem;
        font-weight: 700;
        background: linear-gradient(135deg, #00b4d8 0%, #00d4aa 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 4px;
    }
    
    .page-subtitle {
        color: #64748b;
        font-size: 0.95rem;
        margin-bottom: 24px;
    }
    
    /* Risk indicator */
    .risk-bar-container {
        background: #1a2535;
        border-radius: 8px;
        height: 12px;
        width: 100%;
        overflow: hidden;
        margin: 8px 0;
    }
    
    /* Scrollable log table */
    .log-container {
        max-height: 400px;
        overflow-y: auto;
    }
    
    /* Badge */
    .badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    
    /* Sidebar logo area */
    .sidebar-logo {
        text-align: center;
        padding: 10px 0 20px 0;
        border-bottom: 1px solid #1e3a5f;
        margin-bottom: 20px;
    }
    
    /* Hide Streamlit default elements */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    header { visibility: hidden; }
</style>
"""


def badge(text: str) -> str:
    """Return HTML badge for status values."""
    style = BADGE_STYLES.get(text.upper(), BADGE_STYLES.get("UNAVAILABLE", ""))
    return f'<span style="{style}">{text}</span>'


def metric_card(value, label: str, color: str = "#00b4d8", icon: str = ""):
    """Render a metric card with custom styling."""
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value" style="color: {color};">{icon} {value}</div>
        <div class="metric-label">{label}</div>
    </div>
    """, unsafe_allow_html=True)


def page_header(title: str, subtitle: str = "", icon: str = "🛡️"):
    """Render a page header."""
    st.markdown(f"""
    <div class="page-title">{icon} {title}</div>
    <div class="page-subtitle">{subtitle}</div>
    """, unsafe_allow_html=True)


def decision_banner(decision: str, explanation: str):
    """Display a decision banner (ALLOW/DENY)."""
    if decision == "ALLOW":
        st.markdown(f"""
        <div class="result-allow">
            <h2 style="color: #00d4aa; margin: 0;">✅ ALLOWED</h2>
            <p style="color: #94a3b8; margin: 8px 0 0 0;">{explanation}</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="result-deny">
            <h2 style="color: #ff4b6e; margin: 0;">🚫 DENIED</h2>
            <p style="color: #94a3b8; margin: 8px 0 0 0;">{explanation}</p>
        </div>
        """, unsafe_allow_html=True)


def risk_gauge(score: int, level: str):
    """Create a risk gauge chart."""
    color_map = {
        "LOW": "#00d4aa",
        "MEDIUM": "#ffd32a",
        "HIGH": "#ff9f43",
        "CRITICAL": "#ff4b6e"
    }
    color = color_map.get(level, "#94a3b8")
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": f"Risk Level: {level}", "font": {"color": color, "size": 16}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#64748b", "tickfont": {"color": "#64748b"}},
            "bar": {"color": color},
            "bgcolor": "#1a2535",
            "bordercolor": "#1e3a5f",
            "steps": [
                {"range": [0, 30], "color": "#002e1f"},
                {"range": [30, 60], "color": "#2a2000"},
                {"range": [60, 80], "color": "#2a1500"},
                {"range": [80, 100], "color": "#2d0a14"},
            ],
            "threshold": {
                "line": {"color": color, "width": 4},
                "thickness": 0.75,
                "value": score
            }
        },
        number={"font": {"color": color, "size": 32}}
    ))
    
    fig.update_layout(
        paper_bgcolor="#111827",
        plot_bgcolor="#111827",
        height=250,
        margin=dict(l=20, r=20, t=40, b=20),
        font={"color": "#e2e8f0"}
    )
    
    return fig


def plotly_dark_layout(fig, title: str = "", height: int = 350):
    """Apply consistent dark theme to plotly charts."""
    fig.update_layout(
        title=title,
        paper_bgcolor="#111827",
        plot_bgcolor="#111827",
        font={"color": "#e2e8f0", "family": "Inter, sans-serif"},
        height=height,
        margin=dict(l=20, r=20, t=40, b=30),
        legend=dict(
            bgcolor="#1a2535",
            bordercolor="#1e3a5f",
            borderwidth=1
        ),
        xaxis=dict(
            gridcolor="#1e3a5f",
            linecolor="#1e3a5f",
            tickcolor="#64748b"
        ),
        yaxis=dict(
            gridcolor="#1e3a5f",
            linecolor="#1e3a5f",
            tickcolor="#64748b"
        )
    )
    return fig
