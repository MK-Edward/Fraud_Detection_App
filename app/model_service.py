
import joblib
import pandas as pd
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = BASE_DIR / "artifacts"

FEATURES = [
    "distance_from_home",
    "distance_from_last_transaction",
    "ratio_to_median_purchase_price",
    "repeat_retailer",
    "used_chip",
    "used_pin_number",
    "online_order",
]

NUMERIC_FEATURES = [
    "distance_from_home",
    "distance_from_last_transaction",
    "ratio_to_median_purchase_price",
]


class FraudDetectionService:
    def __init__(self):
        model_path = ARTIFACTS_DIR / "random_forest_model.joblib"
        scaler_path = ARTIFACTS_DIR / "robust_scaler.joblib"

        if not model_path.exists() or not scaler_path.exists():
            raise FileNotFoundError(
                "Missing Random Forest model or RobustScaler in artifacts/."
            )

        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)

    def predict(self, transaction: dict) -> dict:
        X = pd.DataFrame(
            [[transaction[name] for name in FEATURES]],
            columns=FEATURES,
        )

        # Apply the same preprocessing used during training.
        X[NUMERIC_FEATURES] = self.scaler.transform(
            X[NUMERIC_FEATURES]
        )

        prediction = int(self.model.predict(X)[0])

        probability = None
        if hasattr(self.model, "predict_proba"):
            probability = float(self.model.predict_proba(X)[0][1])

        if prediction == 1:
            risk_level = "high"
            decision = "blocked_demo"
        elif probability is not None and probability >= 0.20:
            risk_level = "medium"
            decision = "review_demo"
        else:
            risk_level = "low"
            decision = "approved_demo"

        return {
            "fraud_prediction": prediction,
            "fraud_probability": probability,
            "risk_level": risk_level,
            "decision": decision,
        }
