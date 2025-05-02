import joblib
import re

# Load the trained model
model = joblib.load("phishing_model.pkl")

# Function to extract 7 features (must match model training)
def extract_features_from_url(url):
    features = []

    # 1. UsingIP: IP address in URL?
    features.append(1 if re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", url) else -1)

    # 2. LongURL: Length-based classification
    features.append(1 if len(url) >= 75 else -1 if len(url) <= 54 else 0)

    # 3. ShortURL: Known shortening services
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'is.gd']
    features.append(1 if any(s in url for s in shorteners) else -1)

    # 4. Symbol@: Presence of '@' symbol
    features.append(1 if '@' in url else -1)

    # 5. HTTPS: Uses HTTPS?
    features.append(1 if url.lower().startswith("https") else -1)

    # 6. PrefixSuffix-: Dash in domain
    domain = url.split("//")[-1].split('/')[0]
    features.append(1 if '-' in domain else -1)

    # 7. RequestURL: Suspicious words
    suspicious_keywords = ['login', 'verify', 'bank', 'update', 'secure', 'account']
    features.append(1 if any(word in url.lower() for word in suspicious_keywords) else -1)

    return features

# Ask user for URL input
url = input("🔗 Enter the URL to analyze: ").strip()
features = extract_features_from_url(url)

# Predict
import pandas as pd

# Match the column names used during training
column_names = [
    'UsingIP', 'LongURL', 'ShortURL', 'Symbol@',
    'HTTPS', 'PrefixSuffix-', 'RequestURL'
]

features_df = pd.DataFrame([features], columns=column_names)

# Predict using DataFrame
prediction = model.predict(features_df)[0]


# Output result
if prediction == 1:
    print("🚨 Phishing website detected!")
else:
    print("✅ Website appears to be safe.")
