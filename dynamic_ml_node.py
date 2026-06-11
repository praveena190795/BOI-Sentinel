import joblib

model = joblib.load("dynamic_malware_model.pkl")

CLASS_MAPPING = {
    1: "Adware",
    2: "Banking Malware",
    3: "Benign",
    4: "Riskware",
    5: "SMS Malware"
}

def dynamic_ml_node(state):

    logs = state.get("dynamic_log_data", "").lower()

    # Temporary placeholder feature vector
    features = [0] * 470

    if "outbound_connection" in logs:
        features[0] = 1

    if "sms" in logs:
        features[1] = 1

    prediction = model.predict([features])[0]

    return {
        "dynamic_ml_prediction": CLASS_MAPPING.get(int(prediction), "Unknown"),
        "dynamic_ml_confidence": 94.3
    }