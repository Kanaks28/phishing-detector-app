import streamlit as st
import joblib
import pandas as pd
import re

# Load trained model
model = joblib.load("phishing_model.pkl")

# Feature extractor for URLs
def extract_url_features(url):
    features = []
    features.append(1 if re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", url) else -1)
    features.append(1 if len(url) >= 75 else -1 if len(url) <= 54 else 0)
    features.append(1 if any(s in url for s in ['bit.ly', 'tinyurl', 'goo.gl', 'is.gd']) else -1)
    features.append(1 if '@' in url else -1)
    features.append(1 if url.lower().startswith("https") else -1)
    domain = url.split("//")[-1].split('/')[0]
    features.append(1 if '-' in domain else -1)
    suspicious_keywords = ['login', 'verify', 'bank', 'update', 'secure', 'account']
    features.append(1 if any(word in url.lower() for word in suspicious_keywords) else -1)
    return pd.DataFrame([features], columns=[
        'UsingIP', 'LongURL', 'ShortURL', 'Symbol@',
        'HTTPS', 'PrefixSuffix-', 'RequestURL'
    ])

# Rule-based email detector
def is_phishing_email(email):
    suspicious_words = ['verify', 'update', 'secure', 'alert', 'support', 'login']
    free_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']

    try:
        name, domain = email.split('@')
    except ValueError:
        return "❌ Invalid email format", "error"

    domain = domain.lower()
    name = name.lower()

    # 1. Safe list (whitelist legit domains)
    trusted_domains = ['github.com', 'google.com', 'microsoft.com', 'amazon.com', 'flipkart.com']
    if domain in trusted_domains:
        return "✅ Reputable domain — email looks safe", "success"

    # 2. Suspicious pattern in username (not domain)
    if any(word in name for word in suspicious_words):
        return "🚨 Suspicious username pattern (e.g., verify, support, login)", "error"

    # 3. Free domain with strange username
    if domain in free_domains:
        if len(name) > 10 or not name.isalpha():
             return "⚠️ Possibly suspicious free email ID (unusual format)", "warning"


    # 4. Otherwise safe
    return "✅ Email ID looks safe", "success"

# Streamlit App Tabs
st.title("🛡️ Phishing Detection Tool")

tab1, tab2 = st.tabs(["🔗 Check URL", "📧 Check Email ID"])

# ----- TAB 1: Phishing URL Detector -----
with tab1:
    st.subheader("Phishing URL Detector")
    url_input = st.text_input("Enter URL:", "")

    if st.button("Analyze URL"):
        if url_input:
            features = extract_url_features(url_input)
            prediction = model.predict(features)[0]
            if prediction == 1:
                st.error("🚨 This is likely a phishing website!")
            else:
                st.success("✅ This URL appears safe.")
        else:
            st.warning("Please enter a URL.")

# ----- TAB 2: Phishing Email Detector -----
with tab2:
    st.subheader("Phishing Email ID Detector")
    email_input = st.text_input("Enter Email ID:", "")

    if st.button("Analyze Email"):
        if email_input:
            message, status = is_phishing_email(email_input)
            if status == "error":
                st.error(message)
            elif status == "warning":
                st.warning(message)
            else:
                st.success(message)
        else:
            st.warning("Please enter an email address.")

