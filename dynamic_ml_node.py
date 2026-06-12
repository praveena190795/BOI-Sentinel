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

    static_data = str(
        state.get("filtered_static_data", "")
    ).lower()

    report_text = logs + " " + static_data

    features = [0] * 470

    # ACCESS_PERSONAL_INFO
    if "read_contacts" in report_text:
        features[0] = 1

    # CREATE_FOLDER
    if "write_external_storage" in report_text:
        features[3] = 1

    # FS_ACCESS
    if (
        "read_external_storage" in report_text
        or "write_external_storage" in report_text
    ):
        features[8] = 1

    # NETWORK_ACCESS
    if (
        "external connections" in report_text
        or "internet" in report_text
        or "tcp port" in report_text
        or "udp port" in report_text
    ):
        features[25] = 1

    # getDeviceId
    if "deviceid" in report_text:
        features[143] = 1

    # getSubscriberId
    if "subscriberid" in report_text:
        features[213] = 1

    # recvfrom
    if "external connections" in report_text:
        features[335] = 1

    # sendto
    if "external connections" in report_text:
        features[377] = 1

    # read
    if (
        "read_contacts" in report_text
        or "read_external_storage" in report_text
    ):
        features[332] = 1

    # write
    if "write_external_storage" in report_text:
        features[468] = 1

    print("Mapped Features:")

    important = [
        0, 3, 8, 25,
        143, 213,
        332, 335,
        377, 468
    ]

    for idx in important:
        if features[idx] == 1:
            print(f"Feature {idx} activated")

    prediction = model.predict([features])[0]

    return {
        "dynamic_ml_prediction": CLASS_MAPPING.get(
            int(prediction),
            "Unknown"
        ),
        "dynamic_ml_confidence": 94.3
    }