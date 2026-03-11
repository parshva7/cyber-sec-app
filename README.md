# CyberSecurity Awareness App

A bilingual cybersecurity awareness platform that helps users identify suspicious URLs, stay informed about cyber threats, and learn safe online practices.

## Authors

Parshva Panchal,
Paras Zanzane,
Prathamesh Gharat,
Parth Vaviya,

Department of Artificial Intelligence & Data Science
Dwarkadas J. Sanghvi College of Engineering, Mumbai

Contact: [parshav687@gmail.com](mailto:parshav687@gmail.com)

---

# Project Overview

The rapid growth of online services has increased exposure to cyber threats such as phishing links, malicious websites, and misleading information. This project presents a cybersecurity awareness platform that helps users detect suspicious URLs and stay informed about cybersecurity risks.

The system combines machine learning models, lexical URL analysis, and user-friendly educational tools to help users identify malicious links before interacting with them.

In addition to automated detection, the platform also focuses on improving cybersecurity awareness through news updates and interactive learning modules.

---

# Key Features

### Malicious URL Detection

The platform analyzes URLs using machine learning models trained on phishing and legitimate website datasets.

The system extracts lexical and structural features such as:

* URL length
* Number of dots
* Number of hyphens
* Number of special characters
* Subdomain count
* Suspicious keywords (login, verify, secure, etc.)

These features help identify patterns commonly used in phishing attacks.

---

### Ensemble Machine Learning Model

The system combines multiple machine learning algorithms:

* Random Forest
* Logistic Regression
* XGBoost

A soft-voting ensemble approach is used to improve prediction accuracy and reliability.

---

### Explainable AI

To improve transparency, SHAP (SHapley Additive Explanations) is used to explain predictions.

This allows users to see which features contributed to the classification of a URL as safe or malicious.

Example explanation:

"This URL contains multiple subdomains and suspicious keywords such as 'verify', which are common indicators of phishing."

---

### Bilingual Cybersecurity News

The platform provides cybersecurity news updates using external APIs.

Features include:

* English and Hindi news support
* Voice output for accessibility
* Awareness of current cyber threats

This helps users stay updated with the latest cybersecurity risks.

---

### Cybersecurity Awareness Module

The application includes interactive awareness tools such as:

* Security tips
* Phishing awareness quizzes
* Safe browsing practices
* Password hygiene education

The goal is not only to detect threats but also to build long-term cybersecurity habits.

---

# Dataset

The dataset was collected from publicly available cybersecurity sources:

Phishing URLs from:

* PhishTank
* OpenPhish
* URLHaus

Legitimate URLs from:

* Alexa Top Sites
* Trusted domain repositories

Dataset statistics:

Total URLs: 11,430

* Phishing URLs: 6,377
* Legitimate URLs: 5,053

The dataset includes lexical and structural URL features used for machine learning classification.

---

# Methodology

The URL detection process follows these steps:

1. Input URL is provided by the user.
2. Domain is checked against a whitelist of trusted domains.
3. Lexical features are extracted from the URL.
4. The feature vector is passed to machine learning models.
5. Predictions from all models are combined using soft voting.
6. SHAP values explain the decision to the user.

Final classification:

Safe URL or Phishing URL

---

# Experimental Analysis

Feature analysis shows clear differences between phishing and legitimate URLs.

Key observations:

* Phishing URLs are significantly longer.
* Phishing URLs contain more subdomains.
* Suspicious keywords frequently appear in malicious URLs.
* Higher dot counts often indicate deceptive subdomains.

These patterns validate the effectiveness of lexical feature-based phishing detection.

---

# Technology Stack

Frontend

* React
* JavaScript
* HTML / CSS

Backend

* Node.js
* Express.js
* Python

Machine Learning

* Scikit-learn
* XGBoost
* SHAP

Other Tools

* News API
* Text-to-Speech
* Feature extraction scripts

---

# Project Structure

```
cyber-sec-app
│
├── client
│   ├── React frontend
│
├── server
│   ├── app.py
│   ├── model_train.py
│   ├── url_checker.py
│   ├── dataset_phishing.csv
│   └── requirements.txt
│
├── README.md
└── .gitignore
```

---

# Future Improvements

The system can be enhanced with additional security features:

* SSL certificate validation
* DNS-based analysis
* Real-time model retraining
* Natural language explanations for predictions
* Browser extension integration
* Advanced content-based phishing detection

These improvements can further strengthen detection accuracy and usability.

---

# Conclusion

This project presents a practical cybersecurity awareness platform that combines machine learning, explainable AI, and user education.

The system enables users to detect phishing URLs, understand why a link is unsafe, and stay informed about emerging cyber threats.

By integrating automated detection with awareness tools, the platform promotes safer online behavior and informed decision-making.

---

# References

1. Malicious URL Detection Based on Machine Learning, IJACSA, 2020
2. Detecting Malicious URLs Using Machine Learning Techniques, 2022
3. Edu-SafeLink Mobile-Based Malicious URL Detection, 2025
4. Web Application for Real-Time Phishing Detection, 2023
5. Hybrid Machine Learning Ba
