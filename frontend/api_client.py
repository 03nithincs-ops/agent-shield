"""
AGENT SHIELD - Streamlit Frontend API Client
"""

import requests
import streamlit as st
from typing import Optional, Dict

BASE_URL = "http://localhost:8000"


def api_get(endpoint: str, params: dict = None) -> Optional[dict]:
    """Make a GET request to the backend API."""
    try:
        resp = requests.get(f"{BASE_URL}{endpoint}", params=params, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        st.error("⚠️ Cannot connect to Agent Shield backend. Ensure the backend is running on port 8000.")
        return None
    except requests.exceptions.Timeout:
        st.error("⚠️ Backend request timed out.")
        return None
    except requests.exceptions.HTTPError as e:
        try:
            detail = e.response.json().get("detail", str(e))
        except Exception:
            detail = str(e)
        st.error(f"❌ API Error: {detail}")
        return None
    except Exception as e:
        st.error(f"❌ Unexpected error: {str(e)}")
        return None


def api_post(endpoint: str, data: dict) -> Optional[dict]:
    """Make a POST request to the backend API."""
    try:
        resp = requests.post(f"{BASE_URL}{endpoint}", json=data, timeout=120)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        st.error("⚠️ Cannot connect to Agent Shield backend. Ensure the backend is running on port 8000.")
        return None
    except requests.exceptions.Timeout:
        st.error("⚠️ Backend request timed out.")
        return None
    except requests.exceptions.HTTPError as e:
        try:
            detail = e.response.json().get("detail", str(e))
        except Exception:
            detail = str(e)
        st.error(f"❌ API Error: {detail}")
        return None
    except Exception as e:
        st.error(f"❌ Unexpected error: {str(e)}")
        return None


def api_put(endpoint: str, data: dict) -> Optional[dict]:
    try:
        resp = requests.put(f"{BASE_URL}{endpoint}", json=data, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        st.error("⚠️ Backend not reachable.")
        return None
    except requests.exceptions.HTTPError as e:
        try:
            detail = e.response.json().get("detail", str(e))
        except Exception:
            detail = str(e)
        st.error(f"❌ API Error: {detail}")
        return None
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        return None


def api_patch(endpoint: str, data: dict = None, params: dict = None) -> Optional[dict]:
    try:
        resp = requests.patch(f"{BASE_URL}{endpoint}", json=data, params=params, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        st.error("⚠️ Backend not reachable.")
        return None
    except requests.exceptions.HTTPError as e:
        try:
            detail = e.response.json().get("detail", str(e))
        except Exception:
            detail = str(e)
        st.error(f"❌ API Error: {detail}")
        return None
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        return None


def api_delete(endpoint: str) -> Optional[dict]:
    try:
        resp = requests.delete(f"{BASE_URL}{endpoint}", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        st.error("⚠️ Backend not reachable.")
        return None
    except requests.exceptions.HTTPError as e:
        try:
            detail = e.response.json().get("detail", str(e))
        except Exception:
            detail = str(e)
        st.error(f"❌ API Error: {detail}")
        return None
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        return None


def check_backend_health() -> bool:
    """Check if the backend is reachable."""
    try:
        resp = requests.get(f"{BASE_URL}/health", timeout=3)
        return resp.status_code == 200
    except Exception:
        return False