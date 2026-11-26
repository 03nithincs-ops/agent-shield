"""Trusted Normal-Behaviour Baseline Generator for AGENT SHIELD.

Complying with AVISHKAR'26 Problem Statement 9:
- Generates at least 250 synthetic normal-activity samples per agent.
- Uses reproducible random seeds derived from agent identity.
- Never automatically retrained from incoming untrusted requests (anti-poisoning).
"""
from __future__ import annotations

import hashlib
from typing import Dict, Tuple
import numpy as np


def agent_seed(agent_id: str) -> int:
    """Generate deterministic, reproducible random seed from agent ID."""
    return int(hashlib.sha256(agent_id.encode("utf-8")).hexdigest()[:8], 16)


def generate_normal_baseline(
    agent_id: str,
    req_max: int = 4,
    rec_max: int = 8,
    sample_count: int = 250,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Synthesize trusted normal-behaviour training matrix for an agent.
    
    Returns:
        (X_train, feature_means, feature_stds)
        
    Features generated:
    1. requests_in_window (1 to req_max)
    2. projected_unique_records (1 to rec_max)
    3. unseen_resource_flag (~0 in normal operations)
    4. failed_authz_in_window (~0 in normal operations)
    5. off_hours_flag (~0 in normal operations)
    """
    rng = np.random.default_rng(agent_seed(agent_id))
    n = max(250, int(sample_count))

    # Generate 5-feature baseline distribution
    req = rng.uniform(1.0, float(req_max), size=n)
    rec = rng.uniform(1.0, float(rec_max), size=n)
    unseen = rng.normal(0.0, 0.02, size=n)
    failed = rng.normal(0.0, 0.02, size=n)
    off_hours = rng.normal(0.0, 0.02, size=n)

    raw_matrix = np.column_stack([req, rec, unseen, failed, off_hours])
    means = np.mean(raw_matrix, axis=0)
    stds = np.std(raw_matrix, axis=0)
    stds[stds < 1e-4] = 1.0

    # Apply standardization + composite envelope deviation
    scaled = (raw_matrix - means) / stds
    excess = np.maximum(0.0, np.abs(scaled) - 1.5)
    dev = np.sum(excess, axis=1, keepdims=True)
    X_train = np.hstack([scaled, dev])

    return X_train, means, stds
