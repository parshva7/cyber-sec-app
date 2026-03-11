import re
import pickle
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse
import shap

# ------------------------------
# Load ML Model
# ------------------------------
with open("model.pkl", "rb") as f:
    bundle = pickle.load(f)

model = bundle["model"]
FEATURE_NAMES = bundle["features"]

# ------------------------------
# Suspicious Keywords
# ------------------------------
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "verify", "account", "bank", "update",
    "cash", "free", "bonus"
]

# ------------------------------
# WHITELISTED SAFE DOMAINS
# ------------------------------
WHITELIST_DOMAINS = [

    # ===== BANKS (INDIA) =====
    "hdfcbank.com", "icici.bank.in", "sbi.co.in", "axisbank.com",
    "kotak.com", "yesbank.in", "bankofbaroda.in", "unionbankofindia.co.in",

    # ===== BANKS (GLOBAL) =====
    "chase.com", "bankofamerica.com", "citibank.com",
    "hsbc.com", "standardchartered.com", "dbs.com",
    "ocbc.com", "uob.com.sg", "wellsfargo.com",

    # ===== PAYMENTS / UPI =====
    "paypal.com", "stripe.com", "razorpay.com",
    "paytm.com", "phonepe.com", "googlepay.com",
    "visa.com", "mastercard.com", "americanexpress.com",

    # ===== TECH GIANTS =====
    "microsoft.com", "teams.microsoft.com", "office.com",
    "google.com", "gmail.com", "googleapis.com",
    "apple.com", "icloud.com", "support.apple.com",
    "amazon.com", "aws.amazon.com",

    # ===== SOCIAL MEDIA =====
    "instagram.com", "facebook.com", "fb.com",
    "whatsapp.com", "snapchat.com", "linkedin.com",
    "x.com", "twitter.com", "tiktok.com", "reddit.com",

    # ===== E-COMMERCE =====
    "amazon.in", "flipkart.com", "myntra.com",
    "ajio.com", "ebay.com", "aliexpress.com",

    # ===== GOV / OFFICIAL INDIA =====
    "uidai.gov.in", "gov.in", "nic.in",
    "mygov.in", "incometax.gov.in", "rbi.org.in",
    "nsdl.co.in", "mca.gov.in",

    # ===== NEWS & MEDIA =====
    "bbc.com", "cnn.com", "indiatimes.com",
    "thehindu.com", "economictimes.com", "reuters.com",
    "ndtv.com", "hindustantimes.com",

    # ===== CLOUD / DEV =====
    "github.com", "gitlab.com", "bitbucket.org",
    "vercel.com", "netlify.app", "cloudflare.com",
    "digitalocean.com",

    # ===== STREAMING / ENTERTAINMENT =====
    "netflix.com", "spotify.com",
    "hotstar.com", "primevideo.com", "youtube.com",

    # ===== COMMUNICATION =====
    "zoom.us", "slack.com", "discord.com",
    "telegram.org", "skype.com",

    # ===== BROWSERS & SECURITY =====
    "mozilla.org", "chromium.org", "chrome.com",
    "opera.com", "brave.com", "avg.com", "avast.com"
]


# ------------------------------
# Improved Whitelist Checker
# ------------------------------
def is_whitelisted(domain):
    domain = domain.lower().lstrip("www.")
    for safe in WHITELIST_DOMAINS:
        safe = safe.lower()

        # exact match
        if domain == safe:
            return True

        # matches subdomains
        if domain.endswith("." + safe):
            return True

    return False


# ------------------------------
# Extract URL Features
# ------------------------------
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


# ------------------------------
# SHAP Explainer
# ------------------------------
rf = model.named_estimators_["rf"]
explainer = shap.TreeExplainer(rf)

app = Flask(__name__)
CORS(app)


# ------------------------------
# URL CHECK API
# ------------------------------
@app.route("/check_url", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    parsed = urlparse(url)
    raw_domain = parsed.netloc.split(":")[0].lower()
    clean_domain = raw_domain.lstrip("www.")

    # ----- WHITELIST CHECK -----
    if is_whitelisted(clean_domain):
        result = {
            "url": url,
            "is_malicious": False,
            "malicious_score": 0.0,
            "message": "✅ Safe (whitelisted domain)"
        }
        print("Prediction (whitelisted):", result)
        return jsonify(result)

    # ----- FEATURE EXTRACTION -----
    feats_dict = extract_features(url)
    feat_df = pd.DataFrame([feats_dict])[FEATURE_NAMES]

    # ----- MODEL PREDICTION -----
    proba = float(model.predict_proba(feat_df)[0][1])
    threshold = 0.5
    is_malicious = proba >= threshold

    # ----- SHAP VALUES -----
    shap_values = explainer.shap_values(feat_df)

    if isinstance(shap_values, list):
        shap_vals = shap_values[1][0] if len(shap_values) == 2 else shap_values[0][0]
    else:
        shap_vals = shap_values[0]

    feature_importances = {
        feat: float(val if not isinstance(val, (list, tuple)) else val[0])
        for feat, val in zip(FEATURE_NAMES, shap_vals.tolist())
    }

    sorted_features = sorted(feature_importances.items(), key=lambda x: abs(x[1]), reverse=True)
    top_features = [{"feature": f, "impact": round(i, 4)} for f, i in sorted_features[:5]]

    # ----- FINAL RESPONSE -----
    result = {
        "url": url,
        "is_malicious": is_malicious,
        "malicious_score": round(proba, 3),
        "message": "🚨 Malicious" if is_malicious else "✅ Safe",
        "top_features": top_features
    }
    print("Prediction:", result)
    return jsonify(result)


# ------------------------------
# Run Server
# ------------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055, debug=True)
