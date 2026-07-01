import pandas as pd
import config as C, data_loader as DL, feature_engineering as FE
from inference import _test_split

df = FE.build_features(DL.load_dataset())
ts = pd.to_datetime(df["@timestamp"], utc=True, errors="coerce")
test = _test_split(df, C.SPLIT_RATIOS)

for s in C.SOURCES:
    d_all = df[df["log_source"] == s]
    d = test[test["log_source"] == s]
    if len(d) == 0:
        print(f"{s}: vide"); continue
    span = ts[df["log_source"] == s].max() - ts[df["log_source"] == s].min()
    print(f"\n{s}: total={len(d_all):,} | etendue temporelle={span} | "
          f"procs distincts={d_all['process_name'].nunique()}")
    print(f"  test n={len(d):,}  -- taux de nouveaute sur le test :")
    for f in ["proc_is_new", "parent_child_new", "user_is_new",
              "et_bigram_new", "geo_is_new"]:
        if f in d.columns:
            r = 100 * pd.to_numeric(d[f], errors="coerce").fillna(0).mean()
            print(f"    {f:18s}: {r:5.2f}%")