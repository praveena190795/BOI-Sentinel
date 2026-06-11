import joblib

model = joblib.load("dynamic_malware_model.pkl")

print("Classes:")
print(model.classes_)

print("\nNumber of Features:")
print(model.n_features_in_)