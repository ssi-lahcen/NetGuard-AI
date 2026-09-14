import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder


TARGET_COLUMN = "label"

DROP_COLUMNS = [
    "id",
    "attack_cat"
]

CATEGORICAL_FEATURES = [
    "proto",
    "service",
    "state"
]


def load_datasets(train_path, test_path):
    """
    Load the UNSW-NB15 training and testing datasets.
    """

    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    return train_df, test_df


def prepare_features(train_df, test_df):
    """
    Separate features from the target label.
    """

    X_train = train_df.drop(
        columns=DROP_COLUMNS + [TARGET_COLUMN]
    )

    y_train = train_df[TARGET_COLUMN]

    X_test = test_df.drop(
        columns=DROP_COLUMNS + [TARGET_COLUMN]
    )

    y_test = test_df[TARGET_COLUMN]

    return X_train, X_test, y_train, y_test


def build_preprocessor(X_train):
    """
    Build the preprocessing pipeline for categorical features.
    """

    categorical_features = [
        column
        for column in CATEGORICAL_FEATURES
        if column in X_train.columns
    ]

    numerical_features = [
        column
        for column in X_train.columns
        if column not in categorical_features
    ]

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="ignore"
                ),
                categorical_features
            ),
            (
                "numerical",
                "passthrough",
                numerical_features
            )
        ]
    )

    return preprocessor
