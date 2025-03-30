from flask import Flask, request, jsonify
import tensorflow as tf
import numpy as np

app = Flask(__name__)

# ✅ Load the trained DNN model
MODEL_PATH = "../ml_model/dnn_model.h5"
model = tf.keras.models.load_model(MODEL_PATH)

@app.route("/predict", methods=["POST"])
def predict():
    """Predict if the incoming network flow is an attack or normal."""
    try:
        data = request.json["features"]  # Expecting a list of features
        prediction = model.predict(np.array([data]))[0]  # Make prediction
        predicted_class = int(np.argmax(prediction))  # Get class with highest probability

        return jsonify({"prediction": predicted_class})
    
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
