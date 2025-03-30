import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.model_selection import train_test_split

# Load preprocessed dataset
df = pd.read_csv("../ml_model/preprocessed_kddcup99.csv")

# Split into features (X) and labels (y)
X = df.drop(columns=["label"]).values
y = df["label"].values

# Split dataset into Training and Test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Define Deep Neural Network (DNN) Model
model = Sequential([
    Dense(64, activation="relu", input_shape=(X_train.shape[1],)),  # Input Layer
    Dropout(0.3),  # Dropout for regularization
    Dense(32, activation="relu"),  # Hidden Layer
    Dropout(0.3),
    Dense(1, activation="sigmoid")  # Output Layer (Binary Classification)
])

# Compile Model
model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])

# Train Model with Early Stopping
early_stop = EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True)
history = model.fit(X_train, y_train, validation_data=(X_test, y_test),
                    epochs=50, batch_size=32, callbacks=[early_stop])

# Save Model
model.save("../ml_model/dnn_attack_detection.h5")
print("Model training complete. Saved as dnn_attack_detection.h5.")

# Evaluate Model
loss, accuracy = model.evaluate(X_test, y_test)
print(f"Test Accuracy: {accuracy:.4f}")
