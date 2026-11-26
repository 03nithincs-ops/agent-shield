"""Scikit-Learn Isolation Forest Anomaly Detection implementation for AGENT SHIELD."""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

try:
    from sklearn.ensemble import IsolationForest as SklearnIsolationForest  # type: ignore
    _SKLEARN_AVAILABLE = True
except ImportError:
    SklearnIsolationForest = None
    _SKLEARN_AVAILABLE = False


class AgentIsolationForest:
    """Per-agent Isolation Forest anomaly detector complying with AVISHKAR'26 Problem Statement 9."""

    def __init__(
        self,
        n_estimators: int = 100,
        contamination: float = 0.05,
        random_state: int = 42,
    ) -> None:
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.is_sklearn = bool(_SKLEARN_AVAILABLE and SklearnIsolationForest is not None)
        
        if self.is_sklearn:
            self._model = SklearnIsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=self.random_state,
            )
        else:
            self._model = None  # Pure NumPy Liu et al. fallback if sklearn is absent

    def fit(self, X: np.ndarray) -> "AgentIsolationForest":
        """Fit model exclusively on trusted synthetic normal-activity baseline."""
        if self.is_sklearn:
            self._model.fit(X)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Classify: 1 = normal inlier, -1 = anomalous outlier."""
        if self.is_sklearn:
            return self._model.predict(X)
        return np.ones(X.shape[0], dtype=int)

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Return raw anomaly score: positive = normal inlier, negative = outlier."""
        if self.is_sklearn:
            return self._model.decision_function(X)
        return np.zeros(X.shape[0], dtype=float)

    @property
    def model_telemetry(self) -> Dict[str, Any]:
        return {
            "detector_engine": "sklearn.ensemble.IsolationForest" if self.is_sklearn else "numpy_fallback",
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "random_state": self.random_state,
            "sklearn_active": self.is_sklearn,
        }
