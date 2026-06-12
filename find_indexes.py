import pandas as pd

df = pd.read_csv("feature_vectors_syscallsbinders_frequency_5_Cat.csv")

features = list(df.columns)

targets = [
    "ACCESS_PERSONAL_INFO___",
    "FS_ACCESS____",
    "sendto",
    "recvfrom",
    "read",
    "write",
    "getDeviceId",
    "getSubscriberId",
    "NETWORK_ACCESS____",
    "CREATE_FOLDER_____"
]

for feature in targets:
    if feature in features:
        print(feature, "->", features.index(feature))