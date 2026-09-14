import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

from machine_learning.preprocessing import (
    load_datasets,
    prepare_features,
    build_preprocessor
)


TRAIN_PATH = (
    "datasets/unsw_nb15/"
    "UNSW_NB15_training-set.csv"
)

TEST_PATH = (
    "datasets/unsw_nb15/"
    "UNSW_NB15_testing-set.csv"
)

MODEL_PATH = "machine_learning/netguard_rf.joblib"


def main():
    print("=" * 60)
    print("NetGuard-AI - Machine Learning Training")
    print("=" * 60)

    print("\n[1] Loading datasets...")

    train_df, test_df = load_datasets(
        TRAIN_PATH,
        TEST_PATH
    )

    print(f"Training samples: {len(train_df)}")
    print(f"Testing samples : {len(test_df)}")

    print("\n[2] Preparing features...")

    X_train, X_test, y_train, y_test = prepare_features(
        train_df,
        test_df
    )

    print(f"Input features: {X_train.shape[1]}")

    print("\n[3] Building preprocessor...")

    preprocessor = build_preprocessor(X_train)

    print("\n[4] Encoding features...")

    X_train_processed = preprocessor.fit_transform(X_train)
    X_test_processed = preprocessor.transform(X_test)

    print(
        f"Processed training shape: "
        f"{X_train_processed.shape}"
    )

    print(
        f"Processed testing shape : "
        f"{X_test_processed.shape}"
    )

    print("\n[5] Training Random Forest...")

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )

    model.fit(
        X_train_processed,
        y_train
    )

    print("Training completed.")

    print("\n[6] Evaluating model...")

    y_pred = model.predict(X_test_processed)

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    print(f"\nAccuracy: {accuracy:.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            y_pred,
            target_names=[
                "Normal",
                "Attack"
            ]
        )
    )

    print("Confusion Matrix:")
    print(
        confusion_matrix(
            y_test,
            y_pred
        )
    )

    print("\n[7] Saving model...")

    model_package = {
        "model": model,
        "preprocessor": preprocessor
    }

    joblib.dump(
        model_package,
        MODEL_PATH
    )

    print(f"Model saved to: {MODEL_PATH}")

    print("\n" + "=" * 60)
    print("Training finished")
    print("=" * 60)


if __name__ == "__main__":
    main()
