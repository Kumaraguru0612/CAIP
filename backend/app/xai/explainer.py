try:
    import shap
    HAS_SHAP = True
except (ImportError, Exception):
    shap = None
    HAS_SHAP = False

import pandas as pd
import numpy as np
from typing import Dict, Any, List
from app.intelligence.attack_predictor import AttackPredictor

class SHAPExplainer:
    def __init__(self, predictor: AttackPredictor):
        self.predictor = predictor
        self.explainer = None
        if HAS_SHAP and hasattr(self.predictor, 'risk_model') and self.predictor.risk_model:
            try:
                self.explainer = shap.TreeExplainer(self.predictor.risk_model)
            except Exception:
                self.explainer = None

    def explain_campaign(self, features: Any) -> List[Dict[str, Any]]:
        """
        Generates SHAP explanations showing how each feature contributed to the risk level.
        Accepts either a feature dictionary or a list of campaign events.
        """
        if isinstance(features, list):
            from app.intelligence.feature_extractor import extract_features
            features = extract_features(features)

        clean_features = {f: features.get(f, 0) for f in self.predictor.feature_names}
        df = pd.DataFrame([clean_features], columns=self.predictor.feature_names)
        
        if self.explainer is None:
            # Fallback feature importance calculation from model feature importances
            importances = getattr(self.predictor.risk_model, "feature_importances_", None)
            explanations = []
            for i, name in enumerate(self.predictor.feature_names):
                weight = float(importances[i]) if importances is not None and i < len(importances) else 0.05
                val = clean_features[name]
                contrib = weight * (1.0 if val > 0 else 0.0)
                impact = "positive" if contrib > 0.01 else "neutral"
                explanations.append({
                    "feature": name,
                    "value": val,
                    "shap_value": float(contrib),
                    "impact": impact
                })
            explanations.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
            return explanations

        # Calculate SHAP values
        shap_values = self.explainer.shap_values(df)
        
        # Predict probability to find the target class index (predicted risk level)
        probs = self.predictor.risk_model.predict_proba(df)[0]
        pred_class = int(np.argmax(probs))

        # Handle different SHAP output formats across package versions:
        # 1. Multi-class list of 2D arrays: shape is (classes)[samples, features]
        # 2. Multi-class 3D array: shape is [samples, features, classes]
        # 3. Binary 2D array: shape is [samples, features]
        if isinstance(shap_values, list):
            class_shap = shap_values[pred_class][0]
        elif len(shap_values.shape) == 3:
            class_shap = shap_values[0, :, pred_class]
        elif len(shap_values.shape) == 2:
            class_shap = shap_values[0]
        else:
            class_shap = shap_values

        explanations = []
        for name, val in zip(self.predictor.feature_names, class_shap):
            # Format feature contribution
            impact = "positive" if val > 0.01 else "negative" if val < -0.01 else "neutral"
            explanations.append({
                "feature": name,
                "value": clean_features[name],
                "shap_value": float(val),
                "impact": impact
            })
            
        # Sort by absolute SHAP values (highest magnitude first)
        explanations.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
        return explanations
