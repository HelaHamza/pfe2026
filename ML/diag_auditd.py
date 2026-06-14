import config as C, data_loader as DL
ctx, h = DL._make_es_client()
d = DL._es_request(f"/{C.ES_INDEX}/_search",
    {"size": 5, "query": {"term": {"agent.type": "auditbeat"}}}, ctx=ctx, headers=h)
for hit in d["hits"]["hits"]:
    src = hit["_source"]
    print("module :", repr(DL._dig(src, "event.module")),
          "| dataset :", repr(DL._dig(src, "event.dataset")),
          "| agent :", repr(DL._dig(src, "agent.type")),
          "-> source :", DL._flatten_hit(src)["log_source"])



import config as C, data_loader as DL, pandas as pd
df = DL.load_from_elasticsearch()   # SANS cache, chemin reel du pipeline
print("Repartition log_source :\n", df["log_source"].value_counts())
aud = df[df["log_source"] == "auditd"].copy()
print("\nauditd classes auditd :", len(aud))
if len(aud):
    ts = pd.to_datetime(aud["timestamp"], utc=True, errors="coerce")
    print("NaT parmi auditd :", int(ts.isna().sum()))
    print("min/max :", ts.min(), "->", ts.max())
    print("apres 07/06 :", int((ts >= pd.Timestamp("2026-06-07T21:30:00Z")).sum()))


import config as C, data_loader as DL, pandas as pd
df = DL.load_from_elasticsearch()
ts = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
print("Nombre charge :", len(df), "| plafond MAX_DOCS :", C.MAX_DOCS)
print("timestamp max atteint :", ts.max())   # si c'est ~fin mai, le plafond coupe avant juin