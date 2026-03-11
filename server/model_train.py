import re
import pickle
import pandas as pd
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from xgboost import XGBClassifier

SUSPICIOUS_KEYWORDS = ["login", "secure", "verify", "account", "bank", "update"]

def extract_features(url: str) -> dict:
    url = url.lower()
    parsed = urlparse(url)
    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "has_ip": 1 if re.match(r"^https?://\d+\.\d+\.\d+\.\d+", url) else 0,
        "https_used": 1 if url.startswith("https") else 0,
        "subdomain_count": max(len(parsed.netloc.split(".")) - 2, 0) if parsed.netloc else 0,
        "num_suspicious_words": sum(word in url for word in SUSPICIOUS_KEYWORDS),
        "special_char_count": sum(ch in url for ch in ["%", "=", "&", "?"]),
    }

# Load dataset
df = pd.read_csv("dataset_phishing.csv")
print(f"Dataset loaded: {df.shape[0]} URLs")

X = df["url"].apply(extract_features).apply(pd.Series)
y = df["status"]

# Map string labels 'legitimate'->0, 'phishing'->1
label_map = {"legitimate": 0, "phishing": 1}
y = y.map(label_map)

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Initialize individual models
rf = RandomForestClassifier(n_estimators=200, random_state=42)
lr = LogisticRegression(max_iter=500, solver="lbfgs")
xgb = XGBClassifier(use_label_encoder=False, eval_metric="logloss", random_state=42)

# Train individual models and print accuracies
rf.fit(X_train, y_train)
lr.fit(X_train, y_train)
xgb.fit(X_train, y_train)

rf_acc = rf.score(X_test, y_test)
lr_acc = lr.score(X_test, y_test)
xgb_acc = xgb.score(X_test, y_test)

print(f"Random Forest Accuracy: {rf_acc:.3f}")
print(f"Logistic Regression Accuracy: {lr_acc:.3f}")
print(f"XGBoost Accuracy: {xgb_acc:.3f}")

# Train voting ensemble
ensemble = VotingClassifier(
    estimators=[("rf", rf), ("lr", lr), ("xgb", xgb)],
    voting="soft"
)
ensemble.fit(X_train, y_train)
ensemble_acc = ensemble.score(X_test, y_test)
print(f"Ensemble Accuracy: {ensemble_acc:.3f}")

# Save model and feature names
with open("model.pkl", "wb") as f:
    pickle.dump({"model": ensemble, "features": list(X.columns)}, f)
print("🎯 Model saved to model.pkl")
