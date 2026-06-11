import pandas as pd

df = pd.read_csv("feature_vectors_syscallsbinders_frequency_5_Cat.csv")

print("First 100 Features:\n")
print(df.columns[:100])