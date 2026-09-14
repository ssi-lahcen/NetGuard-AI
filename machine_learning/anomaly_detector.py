import joblib
import pandas as pd


MODEL_PATH = "machine_learning/netguard_rf.joblib"


def load_model(model_path=MODEL_PATH):
    """
    Load the trained Random Forest model and preprocessor.
    """

    model_package = joblib.load(model_path)

    model = model_package["model"]
    preprocessor = model_package["preprocessor"]

    return model, preprocessor


def predict_record(record, model, preprocessor):
    """
    Predict whether a network record is normal or an attack.
    """

    dataframe = pd.DataFrame([record])

    processed_data = preprocessor.transform(
        dataframe
    )

    prediction = model.predict(
        processed_data
    )[0]

    probability = model.predict_proba(
        processed_data
    )[0]

    attack_probability = probability[1]

    if prediction == 1:
        label = "ATTACK"
    else:
        label = "NORMAL"

    return {
        "prediction": label,
        "attack_probability": attack_probability
    }
def predict_dataframe(
    dataframe,
    model,
    preprocessor
):
    """
    Predict multiple network records.
    """

    features = dataframe.drop(
        columns=[
            "id",
            "attack_cat",
            "label"
        ],
        errors="ignore"
    )

    processed_data = preprocessor.transform(
        features
    )

    predictions = model.predict(
        processed_data
    )

    probabilities = model.predict_proba(
        processed_data
    )[:, 1]

    results = dataframe.copy()

    results["ml_prediction"] = predictions
    results["ml_attack_probability"] = probabilities

    results["ml_prediction"] = results[
        "ml_prediction"
    ].map({
        0: "NORMAL",
        1: "ATTACK"
    })

    return results
def generate_ml_alerts(
    dataframe,
    model,
    preprocessor
):
    """
    Generate security alerts from ML predictions.
    """

    features = dataframe.drop(
        columns=[
            "id",
            "attack_cat",
            "label"
        ],
        errors="ignore"
    )

    processed_data = preprocessor.transform(
        features
    )

    predictions = model.predict(
        processed_data
    )

    probabilities = model.predict_proba(
        processed_data
    )[:, 1]

    alerts = []

    for index, prediction in enumerate(predictions):

        if prediction != 1:
            continue

        probability = probabilities[index]

        if probability >= 0.90:
            risk = "HIGH"
        elif probability >= 0.70:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        row = dataframe.iloc[index]

        alert = {
            "alert_type": "ML_ANOMALY",
            "source_ip": row.get("srcip", "Unknown"),
            "destination_ip": row.get("dstip", "Unknown"),
            "prediction": "ATTACK",
            "confidence": float(probability),
            "risk": risk
        }

        alerts.append(alert)

    return alerts
