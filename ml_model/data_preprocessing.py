import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder

# Load Dataset
df = pd.read_csv("../ml_model/kddcup99.csv")  # Ensure correct file path

# Selected 24 Features
selected_features = [
    "wrong_fragment", "duration", "urgent", "land", "protocol_type",
    "service", "flag", "src_bytes", "dst_bytes", "diff_srv_rate",
    "srv_diff_host_rate", "srv_count", "count", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_rerror_rate", "dst_host_srv_diff_host_rate",
    "dst_host_srv_rerror_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate"
]

df = df[selected_features + ["label"]]  # Include label for training

# Convert categorical labels into binary (Normal = 0, Attack = 1)
df["label"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)

# Encode categorical features using One-Hot Encoding
categorical_cols = ["protocol_type", "service", "flag"]
encoder = OneHotEncoder(sparse_output=False, handle_unknown="ignore")
encoded_cols = encoder.fit_transform(df[categorical_cols])

# Convert to DataFrame and get feature names
encoded_df = pd.DataFrame(encoded_cols, columns=encoder.get_feature_names_out(categorical_cols))

# Drop original categorical columns and merge the encoded ones
df.drop(columns=categorical_cols, inplace=True)
df = pd.concat([df, encoded_df], axis=1)

# Normalize numerical features using Z-score normalization
numerical_cols = list(set(selected_features) - set(categorical_cols))
scaler = StandardScaler()
df[numerical_cols] = scaler.fit_transform(df[numerical_cols])

# Save preprocessed data
df.to_csv("../ml_model/preprocessed_kddcup99.csv", index=False)
print("Preprocessing complete. Saved to preprocessed_kddcup99.csv.")
