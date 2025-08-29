from flask import Flask, request, jsonify
import tensorflow as tf
import pickle
from tensorflow.keras.preprocessing.sequence import pad_sequences
import os

# -------------------------
# Paths
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR,  "secret_detector_model.h5")
TOKENIZER_PATH = os.path.join(BASE_DIR,  "tokenizer.pkl")

# -------------------------
# Load model & tokenizer
# -------------------------
model = tf.keras.models.load_model(MODEL_PATH)

with open(TOKENIZER_PATH, "rb") as f:
    tokenizer = pickle.load(f)

MAX_LEN = 750

# -------------------------
# Flask app
# -------------------------
app = Flask(__name__)

@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "OK"})

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    if "texts" not in data or not isinstance(data["texts"], list):
        return jsonify({"error": "Missing 'texts' field or it is not a list"}), 400

    texts = data["texts"]
    
    # Tokenize and pad all texts
    sequences = tokenizer.texts_to_sequences(texts)
    padded = pad_sequences(sequences, maxlen=MAX_LEN, padding='post', truncating='post')

    # Predict probabilities
    probs = model.predict(padded, verbose=0)
    results = [{"text": txt, "prediction": int(p >= 0.5), "probability": float(p)} for txt, p in zip(texts, probs)]

    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
