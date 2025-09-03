import pandas as pd
import numpy as np
import pickle
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Embedding, LSTM, Dense, Dropout, Bidirectional, Concatenate
from tensorflow.keras.optimizers import Adam
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.utils import class_weight
from sklearn.metrics import classification_report, accuracy_score

# =====================
# Detect GPUs & Enable Memory Growth
# =====================
gpus = tf.config.list_physical_devices('GPU')
if gpus:
    print("GPUs found:", gpus)
    for gpu in gpus:
        tf.config.experimental.set_memory_growth(gpu, True)
else:
    print("No GPU detected. Running on CPU.")

# =====================
# Enable Mixed Precision
# =====================
from tensorflow.keras import mixed_precision
policy = mixed_precision.Policy('mixed_float16')
mixed_precision.set_global_policy(policy)
print("Compute dtype:", policy.compute_dtype, "| Variable dtype:", policy.variable_dtype)

# =====================
# Load Dataset
# =====================
df = pd.read_csv("synthetic_secret_dataset.csv")  # CSV must have text,label,entropy,combinations,key_indicators,context_indicators
df["key_indicators"] = df["key_indicators"].fillna("")
df["context_indicators"] = df["context_indicators"].fillna("")
df["text_with_context"] = df["key_indicators"].astype(str) + " " + df["context_indicators"].astype(str) + " " + df["text"].astype(str)

texts = df["text_with_context"].values
numeric_features = df[["entropy", "combinations"]].astype(float).values
labels = df["label"].values  # 0 = Non-secret, 1 = Secret

# =====================
# Train-Test Split
# =====================
X_train_text, X_test_text, X_train_num, X_test_num, y_train, y_test = train_test_split(
    texts, numeric_features, labels, test_size=0.2, random_state=42, stratify=labels
)

# =====================
# Clean & Normalize Numeric Features
# =====================
X_train_num = np.nan_to_num(X_train_num, nan=0.0, posinf=1e6, neginf=-1e6)
X_test_num = np.nan_to_num(X_test_num, nan=0.0, posinf=1e6, neginf=-1e6)

scaler = StandardScaler()
X_train_num = scaler.fit_transform(X_train_num)
X_test_num = scaler.transform(X_test_num)

# =====================
# Compute Class Weights
# =====================
class_weights = class_weight.compute_class_weight(
    class_weight='balanced',
    classes=np.unique(y_train),
    y=y_train
)
class_weights = dict(enumerate(class_weights))
print("Class weights:", class_weights)

# =====================
# Tokenization & Padding
# =====================
max_words = 20000
max_len = 750

tokenizer = Tokenizer(num_words=max_words, oov_token="<OOV>")
tokenizer.fit_on_texts(X_train_text)

with open("tokenizer_with_context.pkl", "wb") as f:
    pickle.dump(tokenizer, f)

X_train_seq = pad_sequences(tokenizer.texts_to_sequences(X_train_text), maxlen=max_len, padding="post", truncating="post")
X_test_seq = pad_sequences(tokenizer.texts_to_sequences(X_test_text), maxlen=max_len, padding="post", truncating="post")

# =====================
# Multi-GPU Strategy
# =====================
strategy = tf.distribute.MirroredStrategy()
print("Number of devices:", strategy.num_replicas_in_sync)

with strategy.scope():
    # =====================
    # Build Model
    # =====================
    text_input = Input(shape=(max_len,), name="text_input")
    x = Embedding(input_dim=max_words, output_dim=128, input_length=max_len)(text_input)
    x = Bidirectional(LSTM(64, return_sequences=True))(x)
    x = Dropout(0.3)(x)
    x = Bidirectional(LSTM(32))(x)
    x = Dense(64, activation="relu")(x)
    x = Dropout(0.3)(x)

    num_input = Input(shape=(X_train_num.shape[1],), name="num_input")
    y = Dense(32, activation="relu")(num_input)
    y = Dropout(0.2)(y)

    combined = Concatenate()([x, y])
    z = Dense(64, activation="relu")(combined)
    z = Dropout(0.3)(z)
    output = Dense(1, activation="sigmoid", dtype='float32')(z)  # ensure output is float32 for mixed precision

    model = Model(inputs=[text_input, num_input], outputs=output)

    optimizer = Adam(learning_rate=1e-4, clipnorm=1.0)
    model.compile(loss="binary_crossentropy", optimizer=optimizer, metrics=["accuracy"])

    model.summary()

# =====================
# Train Model
# =====================
history = model.fit(
    {"text_input": X_train_seq, "num_input": X_train_num},
    y_train,
    validation_split=0.2,
    epochs=5,
    batch_size=128,
    class_weight=class_weights,
    verbose=1
)

# =====================
# Evaluate
# =====================
y_pred_probs = model.predict({"text_input": X_test_seq, "num_input": X_test_num})
y_pred = (y_pred_probs > 0.5).astype("int32")

print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# =====================
# Save Model
# =====================
model.save("secret_detector_model_text_context_gpu.h5")
print("✅ Model saved as secret_detector_model_text_context_gpu.h5")
import joblib
joblib.dump(scaler, "scaler.pkl")
print("✅ Scaler saved as scaler.pkl")