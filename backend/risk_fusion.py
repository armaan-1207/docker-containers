"""
Risk Fusion Engine
==================
Assembles all evidence (CyberIntel, browser features, sandbox features,
consistency report) and produces the final risk verdict.

Bug fix (finding #11 from security review):
  _build_explanations() previously had a `return explanations` statement
  BEFORE the `reduced_confidence` conditional append, making that entire
  branch permanently unreachable dead code. The return is now at the end,
  after all conditionals have been evaluated.

TODO (AI/ML team): Replace predict_probability()'s placeholder with the
trained LightGBM model once it is available. Everything else in this
file (is_placeholder plumbing, thresholds, explanations) is real logic
and should NOT be removed when the model lands -- is_placeholder will
just start evaluating to False automatically once load_model() below
loads a real model object instead of the "MODEL_NOT_AVAILABLE" sentinel.
"""

import random

from config import settings

# Placeholder for the trained model
model = None


def load_model():
    """
    TODO (AI/ML team):
    Load the trained LightGBM model here, e.g.:

        import joblib
        global model
        model = joblib.load(settings.LIGHTGBM_MODEL_PATH)
    """
    global model

    if model is None:
        model = "MODEL_NOT_AVAILABLE"

    return model


def build_feature_vector(features):
    """
    TODO (AI/ML team):
    Convert the collected features into the exact ordered vector the
    trained model expects.
    """
    return features


def predict_probability(feature_vector):
    """
    TODO (AI/ML team): Replace this placeholder with:
        model.predict_proba(feature_vector)
    """
    return round(random.uniform(0.0, 1.0), 2)


def get_risk_level(score):
    if score < settings.SAFE_THRESHOLD:
        return "SAFE"
    elif score < settings.LOW_THRESHOLD:
        return "LOW"
    elif score < settings.MEDIUM_THRESHOLD:
        return "MEDIUM"
    elif score < settings.HIGH_THRESHOLD:
        return "HIGH"
    return "CRITICAL"


def run_risk_fusion(features):

    load_model()

    feature_vector = build_feature_vector(features)

    probability = predict_probability(feature_vector)

    risk_score = round(probability * 100, 2)

    return {
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score),
        "probability": probability,
        # Once load_model() loads a real model, `model` stops being the
        # "MODEL_NOT_AVAILABLE" string and this flips to False on its
        # own -- no other caller needs to change.
        "is_placeholder": model == "MODEL_NOT_AVAILABLE",
    }


class RiskFusionEngine:
    """
    TODO (AI/ML team): once the trained LightGBM model is available,
    build_feature_vector() needs to assemble the *exact* ordered vector
    it expects. Until then this returns a random score, same as
    run_risk_fusion() -- do not treat CRITICAL/HIGH results from this as
    real signal. Downstream (tasks/risk_fusion.py) already refuses to
    fire alerts/incidents while is_placeholder is True -- see that
    file's ALERT_SEVERITIES gate.
    """

    def compute(
        self,
        cyberintel: dict,
        browser_features: dict,
        sandbox_features: dict,
        consistency_report: dict,
    ) -> dict:
        merged_features = {
            "cyberintel": cyberintel or {},
            "browser_features": browser_features or {},
            "sandbox_features": sandbox_features or {},
            "consistency_report": consistency_report or {},
        }

        result = run_risk_fusion(merged_features)

        explanations = self._build_explanations(merged_features, result)

        return {
            "risk_score": result["risk_score"],
            "severity": result["risk_level"],
            "probability": result["probability"],
            "explanations": explanations,
            "iocs": merged_features["cyberintel"].get("iocs", []),
            # Propagated from run_risk_fusion() -- this is the field
            # tasks/risk_fusion.py's alert gate and log line both read.
            # Previously this key was never set on the dict this method
            # returns, so both of those silently no-op'd against a
            # missing key. Fixed here, not there -- this is the single
            # source of truth for "is the score real."
            "is_placeholder": result["is_placeholder"],
        }

    def _build_explanations(self, merged_features: dict, result: dict) -> list:
        """
        Build human-readable explanation strings for the risk verdict.

        Bug fix (finding #11): The original code had `return explanations`
        before the `reduced_confidence` block, making that block permanently
        unreachable. All conditional appends now complete before the return.
        """
        explanations = []

        consistency_report = merged_features["consistency_report"]
        if consistency_report.get("cloaking_suspected"):
            explanations.append("Cloaking suspected: browser and sandbox views disagree.")

        mismatches = consistency_report.get("mismatches") or []
        if mismatches:
            explanations.append(f"Consistency mismatches: {', '.join(mismatches)}.")

        if result.get("is_placeholder"):
            explanations.append(
                "Score generated by placeholder model (LightGBM not yet wired in)."
            )

        # ── Bug fix: this block was unreachable before ──────────────────────
        # The old code returned before reaching here. Now the return is at
        # the bottom of the method so reduced_confidence is always evaluated.
        if consistency_report.get("reduced_confidence"):
            indeterminate = consistency_report.get("indeterminate_categories", [])
            explanations.append(
                f"Consistency score has reduced confidence "
                f"({', '.join(indeterminate) if indeterminate else 'some categories'} "
                f"not yet available)."
            )

        return explanations