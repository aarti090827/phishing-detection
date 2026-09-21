import os
import re
from urllib.parse import urlparse
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# 1. Check if model exists, else create a temporary one automatically
model_path = "MODEL/phishing_model.pkl"

if not os.path.exists(model_path):
    os.makedirs("MODEL", exist_ok=True)
    # Temporary sample training data
    X_train = np.array(
        [
            [18, 10, 0, 1, 0, 0, 0, 0, 2, 1, 0, 14, 0, 0, 0, 0],
            [75, 25, 0, 4, 3, 1, 2, 1, 6, 0, 12, 45, 1, 2, 1, 0],
            [14, 8, 0, 1, 0, 0, 0, 0, 2, 1, 0, 10, 0, 0, 0, 0],
            [60, 20, 1, 3, 2, 0, 1, 1, 5, 0, 8, 35, 1, 1, 0, 0],
        ]
    )
    y_train = np.array([0, 1, 0, 1])

    temp_model = RandomForestClassifier(n_estimators=10, random_state=42)
    temp_model.fit(X_train, y_train)
    joblib.dump(temp_model, model_path)
    print("⚠️ 'phishing_model.pkl' nahi mila, isliye temporary model generate kar diya gaya hai.")

# Load Trained Model
model = joblib.load(model_path)


# 2. Feature Extraction Logic
def extract_features(url):
    features = []

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    features.append(len(url))
    features.append(len(hostname))

    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    features.append(1 if re.match(ip_pattern, hostname) else 0)

    features.append(url.count("."))
    features.append(url.count("-"))
    features.append(url.count("@"))
    features.append(url.count("?"))
    features.append(url.count("="))
    features.append(url.count("/"))
    features.append(1 if url.startswith("https") else 0)
    features.append(sum(c.isdigit() for c in url))
    features.append(sum(c.isalpha() for c in url))

    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "banking",
        "confirm",
        "password",
    ]
    features.append(
        1 if any(word in url.lower() for word in suspicious_keywords) else 0
    )

    subdomains = hostname.split(".")
    features.append(len(subdomains) - 2 if len(subdomains) > 2 else 0)

    shorteners = [
        "bit.ly",
        "goo.gl",
        "tinyurl",
        "t.co",
        "is.gd",
        "cli.gs",
        "ow.ly",
    ]
    features.append(
        1 if any(service in hostname for service in shorteners) else 0
    )
    features.append(1 if "//" in path else 0)

    return features


# 3. Suspicious URL Logic
def suspicious_url(url):
    url = url.lower()

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "security",
        "account",
        "update",
        "confirm",
        "password",
        "signin",
        "banking",
    ]

    suspicious_symbols = ["@"]

    if "-" in url and any(word in url for word in suspicious_words):
        return True

    if url.startswith("http://") or url.startswith("https://"):
        domain = url.split("//")[1].split("/")[0]

        parts = domain.split(".")
        if len(parts) == 4 and all(part.isdigit() for part in parts):
            return True

    if any(symbol in url for symbol in suspicious_symbols):
        return True

    return False


# 4. Main Code Execution
def main():
    url = input("Enter URL: ")

    try:
        if suspicious_url(url):
            result = "⚠️ Phishing Website"
        else:
            features = extract_features(url)
            prediction = model.predict([features])[0]

            if prediction == 1:
                result = "⚠️ Phishing Website"
            else:
                result = "✅ Safe Website"

    except Exception as e:
        result = "Error: " + str(e)

    print("Result:", result)


if __name__ == "__main__":
    main()
  
