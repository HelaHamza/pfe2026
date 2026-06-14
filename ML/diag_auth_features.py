import data_loader as DL, feature_engineering as FE
df = FE.build_features(DL.load_dataset())
a = df[df["log_source"] == "auth"]
print("sum =", a["auth_fail_count_5m"].sum())
print(">0  =", int((a["auth_fail_count_5m"] > 0).sum()))
print(a["event_outcome"].fillna("vide").str.lower().value_counts().head())