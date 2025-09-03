import pickle
import joblib
import numpy as np
import tensorflow as tf
from flask import Flask, request, jsonify
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import math
from collections import Counter

# =====================
# Load Model, Tokenizer & Scaler
# =====================
MODEL_PATH = "secret_detector_model_text_context_gpu.h5"
TOKENIZER_PATH = "tokenizer_with_context.pkl"
SCALER_PATH = "scaler.pkl"

print("Loading model...")
model = load_model(MODEL_PATH)

print("Loading tokenizer...")
with open(TOKENIZER_PATH, "rb") as f:
    tokenizer = pickle.load(f)

print("Loading scaler...")
scaler = joblib.load(SCALER_PATH)

# Config
MAX_LEN = 750

# =====================
# Flask App
# =====================
app = Flask(__name__)

# --- Entropy calculation for a string ---
def calculate_entropy(s: str) -> float:
    length = len(s)
    if length == 0:
        return 0.0

    freq_map = Counter(s)
    entropy = 0.0

    for count in freq_map.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy

def calculate_combinations(s: str) -> float:
    entropy = calculate_entropy(s)
    length = len(s)
    if length == 0:
        return 0.0
    return float(entropy * length)

# --- Preprocessing ---
def preprocess(text, entropy=0.0, combinations=0.0):
    # Sequence encoding
    print("Original text:", text)
    seq = tokenizer.texts_to_sequences([text])
    padded = pad_sequences(seq, maxlen=MAX_LEN, padding="post", truncating="post")
    print("Padded sequence shape:", padded.shape)
    # Numeric features (scaled with saved scaler)
    num_features = np.array([[entropy, combinations]])
    print("Numeric features before scaling:", num_features)
    num_features = scaler.transform(num_features)   # ✅ scale like training

    return {"text_input": padded, "num_input": num_features}

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True)
    text = data.get("text", "")

    # Compute numeric features
    entropy = calculate_entropy(text)
    combinations = calculate_combinations(text)

    # Preprocess input
    inputs = preprocess(text, entropy, combinations)

    # Prediction
    prob = model.predict(inputs)[0][0]
    pred = int(prob > 0.5)

    return jsonify({
        "text": text,
        "prediction": pred,         # 0 = non-secret, 1 = secret
        "probability": float(prob),
        "entropy": float(entropy),
        "combinations": float(combinations)
    })
@app.route("/predict_batch", methods=["POST"])
def predict_batch():
    data = request.get_json(force=True)
    texts = data.get("texts", [])   # expecting a list of strings
    
    if not texts:
        return jsonify({"error": "No texts provided"}), 400

    # Preprocess all
    seqs = tokenizer.texts_to_sequences(texts)
    padded = pad_sequences(seqs, maxlen=MAX_LEN, padding="post", truncating="post")

    entropies = [calculate_entropy(t) for t in texts]
    combinations = [calculate_combinations(t) for t in texts]
    num_features = np.array(list(zip(entropies, combinations)))
    num_features = scaler.transform(num_features)   # ✅ scale numeric features

    # Run inference
    inputs = {"text_input": padded, "num_input": num_features}
    probs = model.predict(inputs)

    # Format results
    results = []
    for text, prob in zip(texts, probs):
        results.append({
            "text": text,
            "prediction": int(prob[0] > 0.5),
            "probability": float(prob[0])
        })

    return jsonify(results)

@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "message": "Secret Detector API running 🚀"})

# =====================
# Run
# =====================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
