# backend/url_checker.py
import pickle

# Load trained model
with open('phishing_model.pkl', 'rb') as file:
    model, vectorizer = pickle.load(file)

def check_url(url):
    X = vectorizer.transform([url])
    prediction = model.predict(X)[0]
    return "Phishing" if prediction == 1 else "Safe"
