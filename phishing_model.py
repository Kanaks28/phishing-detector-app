import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

# Load dataset
df = pd.read_csv("phishing.csv")

# 🧹 Drop Index column if it exists
if 'Index' in df.columns:
    df.drop('Index', axis=1, inplace=True)

# ✅ Rename target column for clarity
df.rename(columns={'class': 'label'}, inplace=True)

# Check data
print("📄 Columns in dataset:", df.columns.tolist())
print("📊 Target value counts:", df['label'].value_counts())

# Features and labels
X = df.drop('label', axis=1)
y = df['label'].replace(-1, 0)  # Make it binary: 0 = Safe, 1 = Phishing

# Select only the 7 relevant features to match your CLI logic
selected_features = [
    'UsingIP', 
    'LongURL', 
    'ShortURL', 
    'Symbol@', 
    'HTTPS', 
    'PrefixSuffix-', 
    'RequestURL'
]


X = df[selected_features]
y = df['label'].replace(-1, 0)

# Split and train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Evaluate
preds = model.predict(X_test)
print("\n📈 Evaluation Report:")
print(classification_report(y_test, preds))

# Save model
joblib.dump(model, 'phishing_model.pkl')
print("\n✅ Model saved as phishing_model.pkl")
