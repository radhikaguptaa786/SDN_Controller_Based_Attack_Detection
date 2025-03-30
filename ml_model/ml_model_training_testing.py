import pandas as pd
import numpy as np
import tensorflow as tf
import joblib
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.model_selection import train_test_split

# ===========================
# 🚀 DATA PREPROCESSING FUNCTION
# ===========================
def preprocess(df, encoder=None, fit_encoder=False):
    """
    Preprocess dataset: One-Hot Encoding for categorical features, Z-score normalization.
    :param df: DataFrame to preprocess
    :param encoder: Pre-fitted OneHotEncoder (for test data)
    :param fit_encoder: Whether to fit the encoder (Only for training data)
    :return: Processed DataFrame, fitted encoder (if applicable)
    """
    selected_features = ["proto","sport", "dport", "state_number", "mean", "stddev", "min", "max", "saddr", "daddr",
        "srate", "drate", "N_IN_Conn_P_SrcIP", "N_IN_Conn_P_DstIP", "attack", "category", "subcategory"]

    df['saddr'] = df['saddr'].apply(ip_to_int)
    df['daddr'] = df['daddr'].apply(ip_to_int)
    
    for col in ['sport', 'dport']:
        df[col] = df[col].apply(lambda x: int(x, 16) if isinstance(x, str) and x.startswith('0x') else x)
    
    categorical_cols= ["proto", "category", "subcategory"]
    numerical_cols = list(set(selected_features) - set(categorical_cols))

    df = df[selected_features].copy()  # Copy to avoid warnings

    # One-Hot Encoding
    if fit_encoder:
        encoder = OneHotEncoder(sparse_output=False, handle_unknown="ignore")
        encoded_cols = encoder.fit_transform(df[categorical_cols])
        joblib.dump(encoder, "onehot_encoder.pkl")  # Save encoder for future use
    else:
        encoded_cols = encoder.transform(df[categorical_cols])

    encoded_df = pd.DataFrame(encoded_cols, columns=encoder.get_feature_names_out(categorical_cols))

    # Drop original categorical columns and merge the encoded ones
    df.drop(columns=categorical_cols, inplace=True)
    df = pd.concat([df, encoded_df], axis=1)

    # Normalize numerical features
    scaler = StandardScaler()
    df[numerical_cols] = scaler.fit_transform(df[numerical_cols])

    return df, encoder


# ===========================
# 🚀 TRAINING THE DNN MODEL
# ===========================
def train_model(train_data_path):
    """
    Train a DNN model on the KDDCup99 dataset.
    :param train_data_path: Path to the training dataset CSV
    """
    # Load dataset
    df = pd.read_csv(train_data_path)

    # Drop unnecessary features
    df = df.drop(columns=["pkSeqID", "seq"])  # Keeping only useful features
    # Convert labels: Normal = 0, Attack = 1
    df["attack"] = df["attack"].apply(lambda x: 0 if x == "normal" else 1)

    # Preprocess data and fit encoder
    X, encoder = preprocess(df, fit_encoder=True)
    y = df["attack"].values  # Labels

    # Split into training and test sets
    X_train, X_test, y_train, y_test = train_test_split(X.values, y, test_size=0.2, random_state=42)

    # Define DNN model
    model = Sequential([
        Dense(64, activation="relu", input_shape=(X_train.shape[1],)),
        Dropout(0.3),
        Dense(32, activation="relu"),
        Dropout(0.3),
        Dense(1, activation="sigmoid")  # Binary classification
    ])

    # Compile model
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])

    # Train model with Early Stopping
    early_stop = EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True)
    model.fit(X_train, y_train, validation_data=(X_test, y_test),
              epochs=5, batch_size=32, callbacks=[early_stop])

    # Save model
    model.save("dnn_model.h5")
    print("✅ Model training complete. Saved as dnn_model.h5.")

    # Evaluate model
    loss, accuracy = model.evaluate(X_test, y_test)
    print(f"📊 Test Accuracy: {accuracy:.4f}")


# ===========================
# 🚀 TESTING WITH NEW DATA
# ===========================
def test_model(test_data_path):
    """
    Load trained model and make predictions on new test data.
    :param test_data_path: Path to the test dataset CSV
    """
    # Load test dataset
    test_df = pd.read_csv(test_data_path)

    # Load trained encoder
    encoder = joblib.load("./onehot_encoder.pkl")

    # Preprocess test data
    X_test, _ = preprocess(test_df, encoder=encoder, fit_encoder=False)

    # Ensure test data has same columns as training
    trained_columns = joblib.load("./trained_columns.pkl")  # Load saved column order
    missing_cols = set(trained_columns) - set(X_test.columns)
    for col in missing_cols:
        X_test[col] = 0  # Add missing columns with default value

    X_test = X_test[trained_columns]  # Reorder columns

    # Load trained model
    model = tf.keras.models.load_model("./dnn_model.h5")

    # Predict
    predictions = model.predict(X_test.values)
    predicted_labels = (predictions > 0.5).astype(int)

    # Save results
    test_df["predicted_label"] = predicted_labels
    test_df.to_csv("test_predictions.csv", index=False)
    print("✅ Predictions saved to test_predictions.csv.")
    return test_df['predicted_label']


# ===========================
# 🚀 MAIN EXECUTION
# ===========================
if __name__ == "__main__":
    # Change file paths as needed
    train_file_path = "./UNSW_2018_IoT_Botnet_Final_10_best_Training.csv"
    test_file_path = "./UNSW_2018_IoT_Botnet_Final_10_best_Testing.csv"

    # Train the model
    train_model(train_file_path)

    # Save feature columns for alignment in test phase
    trained_data = pd.read_csv(train_file_path)
    trained_data, _ = preprocess(trained_data, fit_encoder=True)
    joblib.dump(trained_data.columns.tolist(), "trained_columns.pkl")

    # Test the model on new data
    test_model(test_file_path)
