import pandas as pd

df = pd.read_csv("feature_vectors_syscallsbinders_frequency_5_Cat.csv")

print("Shape:")
print(df.shape)

print("\nLast 10 columns:")
print(df.columns[-10:])

print("\nUnique values in Class:")
print(df["Class"].unique())

print("\nClass Counts:")
print(df["Class"].value_counts())