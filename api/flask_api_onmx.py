from flask import Flask, request, jsonify
import numpy as np
import onnxruntime as ort

app = Flask(__name__)

# ✅ Load ONNX model (No TensorFlow required)
MODEL_PATH = "../ml_model/model.onnx"
session = ort.InferenceSession(MODEL_PATH)

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json["features"]  # Expecting a list of features
        
        print("data",data)
        data_np = np.array([data], dtype=np.float32)  # Convert to NumPy array

        # ONNX model expects dictionary input
        input_name = session.get_inputs()[0].name
        prediction = session.run(None, {input_name: data_np})[0][0]

        predicted_class = int(np.argmax(prediction))  # Get highest probability class

        return jsonify({"prediction": predicted_class})
    
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
