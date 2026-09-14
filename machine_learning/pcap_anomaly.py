import joblib
from sklearn.ensemble import IsolationForest

from machine_learning.pcap_features import (
    extract_flows,
    summarize_flows
)

from machine_learning.pcap_model import (
    flows_to_dataframe
)


MODEL_PATH = "machine_learning/pcap_isolation_forest.joblib"


def train_pcap_model(pcap_path):
    """
    Train an Isolation Forest using normal PCAP traffic.
    """

    flows = extract_flows(pcap_path)
    summaries = summarize_flows(flows)
    dataframe = flows_to_dataframe(summaries)

    if dataframe.empty:
        raise ValueError("No flows were extracted from the PCAP.")

    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
        n_jobs=-1
    )

    model.fit(dataframe)

    joblib.dump(model, MODEL_PATH)

    return model, dataframe


def predict_flows(dataframe, model):
    """
    Predict whether each flow is normal or anomalous.
    """

    predictions = model.predict(dataframe)
    scores = model.decision_function(dataframe)

    results = dataframe.copy()

    results["ml_prediction"] = [
        "NORMAL" if prediction == 1 else "ANOMALY"
        for prediction in predictions
    ]

    results["anomaly_score"] = scores

    return results


if __name__ == "__main__":

    PCAP_PATH = "logs/normal_capture.pcap"

    print("=" * 60)
    print("NetGuard-AI - PCAP Anomaly Detection")
    print("=" * 60)

    print("\n[1] Loading PCAP...")
    print(f"PCAP: {PCAP_PATH}")

    model, dataframe = train_pcap_model(
        PCAP_PATH
    )

    print(f"Flows analyzed: {len(dataframe)}")
    print(f"Features used : {len(dataframe.columns)}")

    print("\n[2] Running anomaly detection...")

    results = predict_flows(
        dataframe,
        model
    )

    normal_count = (
        results["ml_prediction"] == "NORMAL"
    ).sum()

    anomaly_count = (
        results["ml_prediction"] == "ANOMALY"
    ).sum()

    print(f"\nNORMAL flows : {normal_count}")
    print(f"ANOMALY flows: {anomaly_count}")

    print("\n[3] Sample results:")

    print(
        results[
            [
                "ml_prediction",
                "anomaly_score"
            ]
        ].head(10).to_string(index=False)
    )

    print("\n[4] Model saved:")
    print(MODEL_PATH)

    print("\n" + "=" * 60)
    print("PCAP anomaly detection finished")
    print("=" * 60)
