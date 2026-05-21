# tests/test_fusion_real.py
"""
Test réel du FusionRouter sur des données ES existantes.
Corrélation par timestamp+source uniquement.
Lance avec : python3 tests/test_fusion_real.py
"""
import os, sys, ssl, json, base64, urllib.request
import pandas as pd
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))

ES_HOST = os.getenv("ES_HOST",     "https://localhost:9200")
ES_USER = os.getenv("ES_USER",     "elastic")
ES_PASS = os.getenv("ELASTIC_PWD", "pfe2026")


def es_request(path: str, body: dict) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    token   = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    headers = {"Content-Type": "application/json",
               "Authorization": f"Basic {token}"}
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        f"{ES_HOST}{path}", data=data, headers=headers, method="POST"
    )
    resp = urllib.request.urlopen(req, context=ctx)
    return json.loads(resp.read())


def fetch_real_anomalies(limit=20) -> pd.DataFrame:
    body = {
        "size": limit,
        "query": {"term": {"ae_is_anomaly": 1}},
        "sort":  [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp", "log_source", "composite_score",
                    "ae_mse_error", "ae_is_anomaly"],
    }
    try:
        result = es_request("/ml-autoencoder-scores/_search", body)
        rows   = [h["_source"] for h in result["hits"]["hits"]]
        print(f"[REAL] {len(rows)} anomalies AE récupérées")
        return pd.DataFrame(rows)
    except Exception as e:
        print(f"[REAL] Erreur ES anomalies : {e}")
        return pd.DataFrame()


def fetch_real_sigma_alerts(limit=20) -> list:
    body = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp", "alert.title", "alert.level",
                    "alert.tactic", "alert.hits"],
    }
    try:
        result = es_request("/sigma-alerts/_search", body)
        alerts = []
        for hit in result["hits"]["hits"]:
            src = hit["_source"]
            alerts.append({
                "title":      src.get("alert.title", "?"),
                "level":      src.get("alert.level", "?"),
                "tactic":     src.get("alert.tactic", ""),
                "hits":       src.get("alert.hits", 0),
                "es_id":      hit["_id"],
                "@timestamp": src.get("@timestamp", ""),
            })
        print(f"[REAL] {len(alerts)} alertes Sigma récupérées")
        return alerts
    except Exception as e:
        print(f"[REAL] Erreur ES sigma : {e}")
        return []


if __name__ == "__main__":
    from fusion_router import FusionRouter, SOURCE_KEYWORDS, CORRELATION_WINDOW_SECONDS

    df_anomalies = fetch_real_anomalies(limit=20)
    sigma_alerts = fetch_real_sigma_alerts(limit=20)

    if df_anomalies.empty:
        print("[REAL] Aucune anomalie AE — lance d'abord POST /run/analyse")
        sys.exit(1)

    # ── Résumé des données ────────────────────────────────────────────────────
    print(f"\n[REAL] Sources AE : "
          f"{df_anomalies.get('log_source', pd.Series()).value_counts().to_dict()}")
    print(f"[REAL] Fenêtre de corrélation : {CORRELATION_WINDOW_SECONDS}s")

    # ── Construire l'index AE ─────────────────────────────────────────────────
    router = FusionRouter(grok_client=False)
    router._sigma_alerts_cache = sigma_alerts
    router._ae_detections = {}

    mask = df_anomalies.get("ae_is_anomaly", 0) == 1
    for _, row in df_anomalies[mask].iterrows():
        src    = str(row.get("log_source", ""))
        ts_raw = str(row.get("@timestamp", ""))
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            router._ae_detections.setdefault(src, []).append(ts)
        except Exception:
            pass

    print(f"\n[REAL] Index AE :")
    for src, tss in router._ae_detections.items():
        tss_sorted = sorted(tss)
        print(f"  {src}: {len(tss)} timestamps | "
              f"dernier={tss_sorted[-1].isoformat()[:19]}")

    print(f"\n[REAL] Alertes Sigma :")
    for a in sigma_alerts[:5]:
        print(f"  {a.get('@timestamp','?')[:19]} | "
              f"{a.get('title','?')[:45]}")

    # ── Écarts temporels ──────────────────────────────────────────────────────
    print(f"\n[REAL] Écarts AE ↔ Sigma (source mappée) :")
    all_ae_ts = [ts for tss in router._ae_detections.values() for ts in tss]
    if all_ae_ts:
        ae_latest = max(all_ae_ts)
        for a in sigma_alerts[:5]:
            ts_raw = a.get("@timestamp", "")
            try:
                ts_sig = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                delta  = abs((ae_latest - ts_sig).total_seconds())
                src_mapped = next(
                    (s for s, kws in SOURCE_KEYWORDS.items()
                     if any(k in (a.get("tactic","")+" "+a.get("title","")).lower()
                            for k in kws)),
                    "?"
                )
                in_win = "✓ IN" if delta <= CORRELATION_WINDOW_SECONDS else "✗ OUT"
                print(f"  {in_win} {delta:8.0f}s | "
                      f"src={src_mapped:8s} | {a.get('title','?')[:35]}")
            except Exception:
                pass

    # ── Cross-check AE → Sigma ────────────────────────────────────────────────
    print(f"\n[REAL] Cross-check AE → Sigma :")
    print(f"  {'source':8s} {'score':6s} {'timestamp':22s} résultat")
    print(f"  {'-'*60}")

    both_count = ae_only_count = 0
    for _, row in df_anomalies[mask].iterrows():
        anomaly_doc      = row.to_dict()
        detection_source = router._cross_check_sigma(anomaly_doc)
        src   = str(row.get("log_source", "?"))
        score = row.get("composite_score", 0)
        ts    = str(row.get("@timestamp", ""))[:19]
        marker = "  *** BOTH ***" if detection_source == "both" else ""
        print(f"  {src:8s} {str(score):6s} {ts:22s} {detection_source}{marker}")
        if detection_source == "both": both_count += 1
        else: ae_only_count += 1

    # ── Check Sigma → AE ─────────────────────────────────────────────────────
    print(f"\n[REAL] Check Sigma → AE :")
    print(f"  {'titre':45s} ae_corr")
    print(f"  {'-'*55}")

    corr_count = 0
    for alert in sigma_alerts:
        ae_corr = router._check_ae_correlation(alert)
        title   = alert.get("title", "?")[:43]
        marker  = "  *** BOTH ***" if ae_corr else ""
        print(f"  {title:45s} {str(ae_corr)}{marker}")
        if ae_corr: corr_count += 1

    # ── Résumé ────────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"[REAL] RÉSUMÉ")
    print(f"{'='*60}")
    print(f"  Anomalies AE    : {both_count + ae_only_count}")
    print(f"  → both          : {both_count}")
    print(f"  → ae_only       : {ae_only_count}")
    print(f"  Alertes Sigma   : {len(sigma_alerts)}")
    print(f"  → ae_correlated : {corr_count}")
    print(f"{'='*60}")

    if both_count == 0 and corr_count == 0:
        print(f"\n[DIAG] both=0 — cause unique identifiée :")
        if all_ae_ts:
            ae_latest = max(all_ae_ts)
            sig_latest_ts = None
            for a in sigma_alerts:
                try:
                    ts = datetime.fromisoformat(
                        a.get("@timestamp","").replace("Z","+00:00"))
                    if sig_latest_ts is None or ts > sig_latest_ts:
                        sig_latest_ts = ts
                except Exception:
                    pass
            if sig_latest_ts:
                delta = abs((ae_latest - sig_latest_ts).total_seconds())
                print(f"  Écart max AE ↔ Sigma : {delta:.0f}s "
                      f"({delta/3600:.1f}h)")
                print(f"  Fenêtre requise      : {CORRELATION_WINDOW_SECONDS}s")
                if delta > CORRELATION_WINDOW_SECONDS:
                    print(f"  → Les deux analyses ne sont pas simultanées")
                    print(f"  → Lance POST /run/analyse pour aligner les timestamps")