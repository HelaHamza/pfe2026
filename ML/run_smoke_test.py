"""
run_smoke_test.py
=================
Valide TOUT le pipeline SANS Elasticsearch, sur des logs synthetiques.
Sert a verifier qu'on peut "remplacer les fichiers et lancer" sans crash.

  python run_smoke_test.py
"""
from __future__ import annotations
import numpy as np
import pandas as pd

import config as C

# --- Reduire les couts pour le smoke test (avant tout entrainement) ---------
C.USE_CACHE = False
C.EPOCHS_BY_SOURCE = {"auth": 12, "syslog": 10, "auditd": 10}
C.PATIENCE_BY_SOURCE = {"auth": 6, "syslog": 5, "auditd": 5}
C.N_CLEAN_ITERS = 2
C.HDBSCAN_MIN_CLUSTER = 15

import data_loader as DL
import feature_engineering as FE
import training as TR
import inference as INF

rng = np.random.default_rng(0)


def synth_raw(n=6000):
    """Genere des logs ECS bruts plausibles pour les 3 sources."""
    t0 = pd.Timestamp("2026-04-25T00:00:00Z")
    rows = []
    hosts = ["h1", "h2", "h3"]
    users = ["alice", "bob", "root", "svc"]
    ips = [f"10.0.0.{i}" for i in range(5)] + ["8.8.8.8", "45.33.12.9"]
    procs_sys = ["systemd", "kernel", "cron", "NetworkManager", "wpa_supplicant"]
    syscalls = ["execve", "open", "connect", "clone", "mprotect", "ptrace"]
    for i in range(n):
        ts = t0 + pd.Timedelta(seconds=int(rng.integers(0, 30 * 24 * 3600)))
        src = rng.choice(["auth", "syslog", "auditd"], p=[0.35, 0.4, 0.25])
        host = rng.choice(hosts)
        user = rng.choice(users)
        row = dict.fromkeys(DL.RAW_COLUMNS)
        row["timestamp"] = ts.isoformat()
        row["host_name"] = host
        row["user_name"] = user
        if src == "auth":
            row["event_dataset"] = "system.auth"
            row["agent_type"] = "filebeat"
            row["process_name"] = rng.choice(["sshd", "sudo", "su"])
            row["source_ip"] = rng.choice(ips)
            outcome = rng.choice(["success", "failure"], p=[0.85, 0.15])
            row["event_outcome"] = outcome
            row["event_action"] = "ssh_login" if outcome == "success" else "ssh_login_failed"
            # geo simule (peuple par geoip Logstash en vrai). IP privee -> pas de geo.
            row["geo_country"] = (None if str(row["source_ip"]).startswith(("10.", "192.168."))
                                  else rng.choice(["TN", "FR", "US", "RU", "CN"]))
            row["message"] = f"sshd: {outcome} for {user} from {row['source_ip']}"
        elif src == "syslog":
            row["event_dataset"] = "system.syslog"
            row["agent_type"] = "filebeat"
            # Noms parfois parentheses / tronques (cas reel syslog)
            row["process_name"] = rng.choice(procs_sys + ["(haveged)", "gsd-housekeeping"])
            row["event_outcome"] = None
            row["message"] = f"{row['process_name']}: routine event id={i}"
        else:
            row["event_dataset"] = "auditd.log"
            row["event_module"] = "auditd"
            row["agent_type"] = "auditbeat"
            sc = rng.choice(syscalls)
            row["syscall"] = sc
            pname = rng.choice(["bash", "python3", "curl", "nc"])
            row["process_name"] = "" if rng.random() < 0.5 else pname
            row["process_executable"] = "/usr/bin/" + pname
            row["process_args"] = f"{pname} -c task{int(rng.integers(0,9))}"
            row["cmdline"] = row["process_args"]
            row["event_action"] = "executed"
            row["message"] = None
        row["log_source"] = DL._derive_log_source(
            row["event_dataset"], row["agent_type"], row["event_module"])
        rows.append(row)

    # Bruit conteneur Docker (doit etre EXCLU par filter_host_only)
    for k in range(300):
        r = dict.fromkeys(DL.RAW_COLUMNS)
        r.update({
            "timestamp": (t0 + pd.Timedelta(seconds=int(rng.integers(0, 2_000_000)))).isoformat(),
            "host_name": "h1", "agent_type": "auditbeat", "event_module": "auditd",
            "event_dataset": "auditd.log", "syscall": "execve",
            "process_name": "sh", "process_executable": "/usr/bin/bash",
            "process_args": "curl -s https://localhost:9200 health", "event_action": "executed",
            "container_name": "pfe-backend-2026-elasticsearch-1",
        })
        r["log_source"] = DL._derive_log_source(r["event_dataset"], r["agent_type"], r["event_module"])
        rows.append(r)

    # Evenements file_integrity (doivent etre ROUTES en 'unknown' -> ecartes)
    for k in range(50):
        r = dict.fromkeys(DL.RAW_COLUMNS)
        r.update({
            "timestamp": (t0 + pd.Timedelta(seconds=int(rng.integers(0, 2_000_000)))).isoformat(),
            "host_name": "h1", "agent_type": "auditbeat", "event_module": "file_integrity",
            "event_dataset": "file_integrity.event", "event_action": "created",
        })
        r["log_source"] = DL._derive_log_source(r["event_dataset"], r["agent_type"], r["event_module"])
        rows.append(r)

    df = pd.DataFrame(rows, columns=DL.RAW_COLUMNS)

    # Injecter une "rafale" de brute-force auth (meme IP, echecs rapproches)
    burst = []
    bt = t0 + pd.Timedelta(days=10)
    for k in range(40):
        r = dict.fromkeys(DL.RAW_COLUMNS)
        r.update({
            "timestamp": (bt + pd.Timedelta(seconds=k * 3)).isoformat(),
            "host_name": "h1", "user_name": "root", "log_source": "auth",
            "event_dataset": "system.auth", "agent_type": "filebeat",
            "process_name": "sshd", "source_ip": "45.33.12.9",
            "event_outcome": "failure", "event_action": "ssh_login_failed",
            "geo_country": "RU",
            "message": "sshd: failure for root from 45.33.12.9",
        })
        burst.append(r)
    df = pd.concat([df, pd.DataFrame(burst, columns=DL.RAW_COLUMNS)],
                   ignore_index=True)
    # Injecter quelques timestamps invalides (cas reel : @timestamp non parsable)
    bad_idx = rng.choice(len(df), size=5, replace=False)
    df.loc[bad_idx, "timestamp"] = "not-a-date"
    return df


def test_ecs_robustness():
    """Verifie le flatten des champs ECS en LISTE et le round-trip parquet."""
    import data_loader as DL
    # event.action en liste (cas reel ECS) -> doit devenir une chaine
    hit = {"@timestamp": "2026-04-25T00:00:00Z",
           "event": {"action": ["logged-in", "session-opened"],
                     "dataset": "system.auth"},
           "agent": {"type": "filebeat"},
           "process": {"args": ["sshd", "-D"]},
           "host": {"name": "h1"}}
    row = DL._flatten_hit(hit)
    assert isinstance(row["event_action"], str), "event_action non aplati"
    assert row["event_action"] == "logged-in session-opened"
    assert isinstance(row["process_args"], str)
    # round-trip parquet : aucune colonne ne doit contenir de liste
    pd.DataFrame([row], columns=DL.RAW_COLUMNS).to_parquet("/tmp/_rt.parquet")
    pd.read_parquet("/tmp/_rt.parquet")
    print("    flatten listes ECS + parquet round-trip : OK")


def main():
    print(">>> Generation de logs synthetiques")
    df_raw = synth_raw()
    print(f"    {len(df_raw):,} logs ;",
          df_raw['log_source'].value_counts().to_dict())

    print("\n>>> Robustesse ECS (listes + parquet + NaT)")
    test_ecs_robustness()

    # Brancher le loader synthetique partout
    # Brancher le loader synthetique partout, en passant par le filtre host-only
    # (exclusion conteneur) et en ecartant les 'unknown' (routage), comme le vrai
    # load_from_elasticsearch.
    def _synth_loader(*a, **k):
        d = df_raw.copy()
        d = d[d["log_source"] != "unknown"].reset_index(drop=True)
        return DL.filter_host_only(d)
    DL.load_dataset = _synth_loader
    INF.DL.load_dataset = _synth_loader

    print("\n>>> Exclusion conteneur + routage modules")
    n_before = len(df_raw)
    df_host = _synth_loader()
    print(f"    {n_before:,} bruts -> {len(df_host):,} host-only "
          f"(conteneurs + file_integrity ecartes)")
    assert (df_host["container_name"].fillna("") == "").all(), "bruit conteneur non exclu !"
    assert "unknown" not in df_host["log_source"].unique(), "routage modules casse !"
    assert set(df_host["log_source"].unique()) <= {"auth", "syslog", "auditd"}

    print("\n>>> Filtre temporel par source (auditd borne)")
    _tw = pd.DataFrame({
        "timestamp": ["2026-06-07T20:00:00Z", "2026-06-07T22:00:00Z",
                      "2026-01-01T00:00:00Z"],
        "log_source": ["auditd", "auditd", "syslog"],
    })
    _orig = (C.DATA_START_BY_SOURCE, C.DATA_END_BY_SOURCE)
    C.DATA_START_BY_SOURCE = {"auditd": "2026-06-07T21:30:00Z", "syslog": None, "auth": None}
    C.DATA_END_BY_SOURCE = {"auditd": None, "syslog": None, "auth": None}
    _kept = DL.filter_time_window(_tw)
    C.DATA_START_BY_SOURCE, C.DATA_END_BY_SOURCE = _orig
    assert len(_kept) == 2, "filtre temporel : mauvais compte"
    assert "2026-06-07T20:00:00Z" not in _kept["timestamp"].values, "auditd pre-bascule non coupe !"
    assert "2026-01-01T00:00:00Z" in _kept["timestamp"].values, "syslog historique coupe a tort !"
    print("    auditd pre-bascule coupe, syslog historique conserve : OK")

    print("\n>>> Verification features (causales)")
    df_feat = FE.build_features(df_host)
    issues = FE.validate_feature_coverage(df_feat)
    assert "auth_fail_count_5m" in df_feat.columns
    fmax = df_feat.loc[df_feat.log_source == "auth", "auth_fail_count_5m"].max()
    print(f"    auth_fail_count_5m max = {fmax}  (doit etre > 5 grace a la rafale)")
    assert fmax > 5, "la rafale brute-force n'est pas captee !"
    assert df_feat["is_root"].sum() > 0, "is_root jamais positif !"
    print(f"    is_root positifs = {int(df_feat['is_root'].sum())}")
    print(f"    bigrammes nouveaux = {int(df_feat['et_bigram_new'].sum())}")
    print(f"    proc_is_new positifs = {int(df_feat['proc_is_new'].sum())}")
    ext = int(df_feat.loc[df_feat.log_source == 'auth', 'ip_is_external'].sum())
    geo = int(df_feat.loc[df_feat.log_source == 'auth', 'geo_is_new'].sum())
    print(f"    ip_is_external (auth) positifs = {ext}")
    print(f"    geo_is_new (auth) positifs = {geo}")
    assert ext > 0, "ip_is_external toujours nul -> bug non corrige !"
    assert geo > 0, "geo_is_new toujours nul -> bug non corrige !"
    aud_new = int(df_feat.loc[df_feat.log_source == 'auditd', 'proc_is_new'].sum())
    print(f"    proc_is_new (auditd) positifs = {aud_new}")
    assert aud_new > 0, "proc_is_new auditd nul -> repli executable casse !"
    # Normalisation : '(haveged)' et 'gsd-housekeeping' canonicalises
    assert FE._canonical_proc("(haveged)") == "haveged"
    assert FE._canonical_proc("gsd-housekeeping") == FE._canonical_proc("gsd-housekeepin")
    print("    normalisation process_name (parentheses + 15 car.) : OK")

    print("\n>>> Entrainement complet (epochs reduits)")
    out = TR.main()
    assert out is not None, "training.main a echoue"

    print("\n>>> Inference + diagnostics + episodes")
    INF.main()

    print("\n>>> SMOKE TEST OK")


if __name__ == "__main__":
    main()