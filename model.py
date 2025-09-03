import pandas as pd
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.utils import class_weight
from sklearn.metrics import classification_report, accuracy_score
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Embedding, LSTM, Dense, Dropout, Bidirectional, Concatenate
from tensorflow.keras.optimizers import Adam

# =====================
# Load Dataset
# =====================
# CSV must have: text,label,entropy,combinations,key_indicators,context_indicators
df = pd.read_csv("synthetic_secret_dataset.csv")  # Replace with your file

# Fill missing indicators
df["key_indicators"] = df["key_indicators"].fillna("")
df["context_indicators"] = df["context_indicators"].fillna("")

# Combine indicators into text
df["text_with_context"] = (
    df["key_indicators"].astype(str) + " " +
    df["context_indicators"].astype(str) + " " +
    df["text"].astype(str)
)

texts = df["text_with_context"].values
numeric_features = df[["entropy", "combinations"]].astype(float).values
labels = df["label"].values  # 0 = Non-secret, 1 = Secret

print(f"Dataset size: {len(texts)} samples")

# =====================
# Data Sanity Checks
# =====================
def print_data_stats(texts, numeric_features, labels):
    print("Text sample:", texts[0])
    print("Numeric features min/max:", np.min(numeric_features, axis=0), np.max(numeric_features, axis=0))
    print("Labels unique:", np.unique(labels))
    print("Any NaN in numeric features:", np.isnan(numeric_features).any())
    print("Any NaN in labels:", np.isnan(labels).any() if np.issubdtype(labels.dtype, np.number) else False)
    print("Any NaN in texts:", pd.isnull(texts).any())
    print("Any inf in numeric features:", np.isinf(numeric_features).any())

print_data_stats(texts, numeric_features, labels)

# =====================
# Train-Test Split
# =====================
X_train_text, X_test_text, X_train_num, X_test_num, y_train, y_test = train_test_split(
    texts, numeric_features, labels, test_size=0.2, random_state=42, stratify=labels
)

print(f"Training samples: {len(X_train_text)}, Testing samples: {len(X_test_text)}")

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
max_words = 20000   # vocab size
max_len = 750       # max length of each text

tokenizer = Tokenizer(num_words=max_words, oov_token="<OOV>")
tokenizer.fit_on_texts(X_train_text)

with open("tokenizer_with_context.pkl", "wb") as f:
    pickle.dump(tokenizer, f)

X_train_seq = pad_sequences(tokenizer.texts_to_sequences(X_train_text), maxlen=max_len, padding="post", truncating="post")
X_test_seq = pad_sequences(tokenizer.texts_to_sequences(X_test_text), maxlen=max_len, padding="post", truncating="post")

print("✅ Tokenizer saved as tokenizer_with_context.pkl")

# =====================
# Build LSTM Model
# =====================
# Text input (with indicators)
text_input = Input(shape=(max_len,), name="text_input")
x = Embedding(input_dim=max_words, output_dim=128, input_length=max_len)(text_input)
x = Bidirectional(LSTM(64, return_sequences=True))(x)
x = Dropout(0.3)(x)
x = Bidirectional(LSTM(32))(x)
x = Dense(64, activation="relu")(x)
x = Dropout(0.3)(x)

# Numeric input (entropy + combinations)
num_input = Input(shape=(X_train_num.shape[1],), name="num_input")
y = Dense(32, activation="relu")(num_input)
y = Dropout(0.2)(y)

# Concatenate text and numeric features
combined = Concatenate()([x, y])
z = Dense(64, activation="relu")(combined)
z = Dropout(0.3)(z)
output = Dense(1, activation="sigmoid")(z)

model = Model(inputs=[text_input, num_input], outputs=output)

# Optimizer with lower LR + gradient clipping
optimizer = Adam(learning_rate=1e-4, clipnorm=1.0)
model.compile(loss="binary_crossentropy", optimizer=optimizer, metrics=["accuracy"])
model.summary()

# =====================
# Train Model with Class Weights
# =====================
history = model.fit(
    {"text_input": X_train_seq, "num_input": X_train_num},
    y_train,
    validation_split=0.2,
    epochs=5,
    batch_size=128,
    verbose=1,
    class_weight=class_weights
)

# =====================
# Evaluate
# =====================
y_pred_probs = model.predict({"text_input": X_test_seq, "num_input": X_test_num})
y_pred = (y_pred_probs > 0.5).astype("int32")  # Can adjust threshold if needed

print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# =====================
# Save Model
# =====================
model.save("secret_detector_model_text_context.h5")
print("✅ Model saved as secret_detector_model_text_context.h5")
