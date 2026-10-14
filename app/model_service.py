import joblib
import pandas as pd
import numpy as np
from pathlib import Path

class FraudDetectionService:
    def __init__(self):
        self.artifacts_dir = Path("artifacts")
        self.model_path = self.artifacts_dir / "random_forest_model.joblib"
        self.scaler_path = self.artifacts_dir / "robust_scaler.joblib"
        self.features_path = self.artifacts_dir / "features.joblib"

        for path in [self.model_path, self.scaler_path, self.features_path]:
            if not path.exists():
                raise FileNotFoundError(f"Missing required artifact file at: {path}")

        self.model = joblib.load(self.model_path)
        self.scaler = joblib.load(self.scaler_path)
        self.features_list = joblib.load(self.features_path)

    def predict(self, data) -> dict:
        input_dict = data.model_dump()
        df = pd.DataFrame([input_dict])
        
        try:
            scaler_features = list(self.scaler.feature_names_in_)
        except AttributeError:
            scaler_features = ["distance_from_home", "distance_from_last_transaction", "ratio_to_median_purchase_price"]

        processed_df = df.copy()
        processed_df[scaler_features] = self.scaler.transform(df[scaler_features])
        processed_df = processed_df[self.features_list]
        
        prediction = int(self.model.predict(processed_df)[0])
        
        try:
            probabilities = self.model.predict_proba(processed_df)
            probability = float(probabilities[0][1])  # Extract probability of class 1 (Fraud)
        except (AttributeError, IndexError, TypeError):
            probability = 1.0 if prediction == 1 else 0.0

        risk_level = "High" if probability >= 0.7 else "Medium" if probability >= 0.3 else "Low"
        decision = "Review / Block" if prediction == 1 else "Approve"

        return {
            "fraud_prediction": prediction,
            "fraud_probability": probability,
            "risk_level": risk_level,
            "decision": decision
        }
