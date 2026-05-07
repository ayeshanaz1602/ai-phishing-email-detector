import pandas as pd
import re

from colorama import Fore, init

init()
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, confusion_matrix

# Load dataset
data = pd.read_csv("Phishing_Email.csv")

# Features and labels
X = data["text_combined"]
y = data["label"]

# Convert text into numbers
vectorizer = TfidfVectorizer()

X_vectorized = vectorizer.fit_transform(X)

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X_vectorized, y, test_size=0.2, random_state=42
)

# Train model
model = MultinomialNB()

model.fit(X_train, y_train)

# Predictions
y_pred = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, y_pred)

print("\n==============================")
print(" MODEL PERFORMANCE")
print("==============================")

print(f"Accuracy: {accuracy * 100:.2f}%")

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)

print("\n==============================")
print(" CONFUSION MATRIX")
print("==============================")

print(cm)

print("\nMatrix Meaning:")
print("TN  FP")
print("FN  TP")

# Test custom email
email = input("\nEnter an email message: ")

email_vector = vectorizer.transform([email])

prediction = model.predict(email_vector)

# URL Detection
urls = re.findall(r'https?://\S+|www\.\S+', email)

suspicious_domains = ["bit.ly", "tinyurl", "verify", "login", "secure"]

suspicious_found = False
reasons = []

urgent_words = [
    "urgent",
    "verify",
    "bank",
    "password",
    "otp",
    "click",
    "reward",
    "suspended"
]

reasons = []

urgent_words = [
    "urgent",
    "verify",
    "bank",
    "password",
    "otp",
    "click",
    "reward",
    "suspended"
]

for url in urls:
    for word in suspicious_domains:
        if word in url:
            suspicious_found = True
            reasons.append("Suspicious URL detected")

# Keyword Detection
email_lower = email.lower()

for word in urgent_words:
    if word in email_lower:
        reasons.append(f"Suspicious keyword detected: {word}")

# Final Result
print("\n==============================")
print(" EMAIL THREAT ANALYSIS")
print("==============================")

if prediction[0] == 1 or suspicious_found:

    print(Fore.RED + "⚠️ Threat Level: HIGH")
    print(Fore.RED + "Prediction: PHISHING")

    print("\nReasons:")

    for reason in set(reasons):
        print(f"- {reason}")

    if urls:
        print(f"\nSuspicious URLs Found: {len(urls)}")

else:
    print("✅ Threat Level: LOW")
    print(Fore.GREEN + "Prediction: SAFE")