import joblib
import pandas as pd

# Load model
model = joblib.load("dynamic_malware_model.pkl")

# Load dataset
df = pd.read_csv("feature_vectors_syscallsbinders_frequency_5_Cat.csv")

# Remove label column
X = df.drop("Class", axis=1)

# Feature importance
importance = model.feature_importances_

# Create table
feature_df = pd.DataFrame({
    "Feature": X.columns,
    "Importance": importance
})

# Sort descending
feature_df = feature_df.sort_values(
    by="Importance",
    ascending=False
)

print(feature_df.head(50))