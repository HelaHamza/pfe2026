"""
=============================================================================
MIXTURE-OF-EXPERTS AUTOENCODER IDS
=============================================================================
Un seul modèle, un seul entraînement.
Chaque source a son encodeur/décodeur expert + des features partagées.
Le gradient ne touche que l'expert actif → pas de pollution cross-source.
=============================================================================
"""

import json, ssl, urllib.request, base64, warnings, joblib, time, os
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset, WeightedRandomSampler
from datetime import datetime, timezone
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import roc_auc_score, average_precision_score, \
    precision_score, recall_score, f1_score, confusion_matrix
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings("ignore")

np.random.seed(42)
torch.manual_seed(42)
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ===========================================================================
# CONFIGURATION
# ===========================================================================
ES_HOST       = "https://localhost:9200"
ES_USER       = "elastic"

ES_INDEX_READ = "filebeat-logs-*,auditbeat-*"
ES_INDEX_WRITE= "ml-autoencoder-scores"

MODEL_PATH    = "model_moe_ae.pt"
SCALERS_PATH  = "moe_scalers.pkl"   # dict {src: scaler}
ENCODERS_PATH = "moe_encoders.pkl"
THRESH_PATH   = "moe_thresholds.pkl"
PLOTS_DIR     = "moe_plots"

SOURCES       = ["syslog", "auth", "auditd"]
LATENT_DIM    = 12
BATCH_SIZE    = 256
EPOCHS        = 150
LR            = 1e-3
WEIGHT_DECAY  = 1e-5
ANOMALY_PCT   = 99
NORMAL_THR    = 2      # composite_score < 2 → normal

# ===========================================================================
# FEATURES PAR SOURCE  (disjointes — reflète exactement le filtre Logstash)
# ===========================================================================

# Features présentes dans TOUTES les sources (section 2 + 3 du filtre)
SHARED_FEATURES = [
    "hour_of_day", "day_of_week",
    "is_off_hours", "is_night", "is_weekend", "is_business",
    "hour_sin", "hour_cos",
    "msg_length_log", "msg_word_count",
    "msg_has_ip", "msg_has_base64", "msg_has_url",
    "is_root", "user_sensitivity",
    "delta_time_log",
    "log_source_encoded",
]

# Features spécifiques à chaque source
EXPERT_FEATURES = {
    "syslog": [
        "sys_oom_kill", "sys_module_load", "sys_cron_new_job",
        "sys_firewall_change", "sys_service_crash_loop",
        "sys_msg_length_log", "sys_lateral_ssh", "sys_new_service",
        "sys_log_tamper", "sys_high_cpu_process",
        "freq_spike_ratio", "freq_spike_ratio_5m",
        "event_count_ip", "event_count_1m_ip", "event_count_5m_ip",
        "cross_multi_source",
    ],
    "auth": [
        "auth_is_root", "auth_ip_is_external",
        "auth_severity", "auth_sev_norm",
        "auth_user_sensitivity",
        "auth_user_created", "auth_user_deleted",
        "auth_sudo_to_root", "auth_passwd_changed",
        "auth_pam_open", "auth_pam_close", "auth_known_country",
        "auth_fail_count_5m", "auth_fail_window_10m",
        "auth_ok_count_5m", "auth_fail_ratio",
        "auth_users_tried", "unique_users_per_ip",
        "auth_is_brute_force", "auth_is_slow_bruteforce",
        "auth_is_user_enum", "auth_is_stuffing",
        "session_duration_log",
        "cross_ssh_then_sudo", "cross_bruteforce_success",
        "freq_spike_ratio", "event_count_ip",
    ],
    "auditd": [
        "aud_severity", "aud_sev_norm",
        "aud_ptrace", "aud_process_injection", "aud_log_tamper",
        "aud_cmd_entropy", "aud_cmd_length_log", "aud_cmd_is_obfuscated",
        "aud_arg_count", "payload_size_log",
        "aud_reverse_shell", "aud_cron_backdoor", "aud_suid_abuse",
        "aud_ld_hijack", "aud_credential_access", "aud_ssh_key_implant",
        "aud_cryptominer", "aud_log_delete", "aud_network_scan",
        "aud_exfiltration",
        "delta_time_log", "event_count_ip",
    ],
}

SHARED_DIM  = len(SHARED_FEATURES)
EXPERT_DIMS = {s: len(f) for s, f in EXPERT_FEATURES.items()}

# ===========================================================================
# SECTION 1 — ARCHITECTURE MoE-AE
# ===========================================================================

def make_encoder(input_dim, latent_dim):
    """Encodeur MLP : input → latent."""
    hidden = max(input_dim * 2, 32)
    return nn.Sequential(
        nn.Linear(input_dim, hidden), nn.BatchNorm1d(hidden),
        nn.ReLU(), nn.Dropout(0.1),
        nn.Linear(hidden, hidden // 2), nn.BatchNorm1d(hidden // 2),
        nn.ReLU(), nn.Dropout(0.1),
        nn.Linear(hidden // 2, latent_dim),
    )

def make_decoder(latent_dim, output_dim):
    """Décodeur MLP : latent → reconstruction."""
    hidden = max(output_dim * 2, 32)
    return nn.Sequential(
        nn.Linear(latent_dim, hidden // 2), nn.BatchNorm1d(hidden // 2),
        nn.ReLU(), nn.Dropout(0.1),
        nn.Linear(hidden // 2, hidden), nn.BatchNorm1d(hidden),
        nn.ReLU(), nn.Dropout(0.1),
        nn.Linear(hidden, output_dim),
    )

class MoEAutoencoder(nn.Module):
    """
    Mixture-of-Experts Autoencoder.

    Flux :
      x_shared  → shared_encoder  → z_shared  (latent_dim)
      x_expert  → expert_encoder  → z_expert  (latent_dim)
      z = z_shared + z_expert      → espace latent commun
      z → shared_decoder           → x̂_shared
      z → expert_decoder           → x̂_expert

    Avantages vs SCA :
      - Les features à variance nulle (auditd dans syslog) ne sont
        jamais vues par l'expert syslog → pas de bruit artificiel
      - Le gradient ne touche que l'expert actif
      - Un seul fichier .pt, un seul entraînement, une seule API
      - Les seuils sont calibrés séparément par source comme avant
    """

    def __init__(self, shared_dim, expert_dims, latent_dim=LATENT_DIM):
        super().__init__()
        self.shared_dim  = shared_dim
        self.expert_dims = expert_dims
        self.latent_dim  = latent_dim

        # Encodeur partagé
        self.shared_encoder = make_encoder(shared_dim, latent_dim)

        # Décodeur partagé
        self.shared_decoder = make_decoder(latent_dim, shared_dim)

        # Experts par source
        self.expert_encoders = nn.ModuleDict({
            src: make_encoder(dim, latent_dim)
            for src, dim in expert_dims.items()
        })
        self.expert_decoders = nn.ModuleDict({
            src: make_decoder(latent_dim, dim)
            for src, dim in expert_dims.items()
        })

    def forward(self, x_shared, x_expert, src_name):
        """
        x_shared : (B, shared_dim)
        x_expert : (B, expert_dim[src_name])
        src_name : str  "syslog" | "auth" | "auditd"
        """
        z_shared = self.shared_encoder(x_shared)
        z_expert = self.expert_encoders[src_name](x_expert)
        z = z_shared + z_expert          # fusion additive dans l'espace latent

        x_shared_hat = self.shared_decoder(z)
        x_expert_hat = self.expert_decoders[src_name](z)

        return x_shared_hat, x_expert_hat, z

    def reconstruction_error(self, x_shared, x_expert, src_name):
        self.eval()
        with torch.no_grad():
            xsh, xex, _ = self.forward(x_shared, x_expert, src_name)
            mse_shared = ((x_shared - xsh) ** 2).mean(dim=1)
            mse_expert = ((x_expert - xex) ** 2).mean(dim=1)
            # MSE combinée : poids 0.4 shared + 0.6 expert
            # L'expert est plus discriminant (features spécifiques à la source)
            mse = 0.4 * mse_shared + 0.6 * mse_expert
        return mse.cpu().numpy()


# ===========================================================================
# SECTION 2 — PRÉTRAITEMENT PAR SOURCE
# ===========================================================================

def safe_float(v, d=0.0):
    try:
        f = float(v)
        return d if (np.isnan(f) or np.isinf(f)) else f
    except: return d

def safe_int(v, d=0):
    try:
        f = float(v)
        return d if (np.isnan(f) or np.isinf(f)) else int(f)
    except: return d


def preprocess_source(df_src, src_name, scaler_shared=None,
                      scaler_expert=None, fit=True):
    """
    Prétraite les events d'une seule source.
    Retourne (X_shared, X_expert, scaler_shared, scaler_expert).
    """
    df = df_src.copy()

    def get_col(col):
        if col not in df.columns:
            return pd.Series(np.zeros(len(df)), index=df.index)
        return pd.to_numeric(df[col], errors="coerce").fillna(0)

    # Shared
    X_sh = np.stack([get_col(c).values for c in SHARED_FEATURES], axis=1).astype(np.float32)
    X_sh = np.nan_to_num(X_sh, nan=0.0, posinf=0.0, neginf=0.0)

    # Expert
    expert_cols = EXPERT_FEATURES[src_name]
    X_ex = np.stack([get_col(c).values for c in expert_cols], axis=1).astype(np.float32)
    X_ex = np.nan_to_num(X_ex, nan=0.0, posinf=0.0, neginf=0.0)

    if fit:
        scaler_shared = StandardScaler().fit(X_sh)
        scaler_expert = StandardScaler().fit(X_ex)

    X_sh = scaler_shared.transform(X_sh).astype(np.float32)
    X_ex = scaler_expert.transform(X_ex).astype(np.float32)

    return X_sh, X_ex, scaler_shared, scaler_expert


# ===========================================================================
# SECTION 3 — CHARGEMENT ES
# ===========================================================================

def make_es_client():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    token = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    headers = {"Content-Type": "application/json",
               "Authorization": f"Basic {token}"}
    return ctx, headers

def es_request(path, body=None, method=None, ctx=None, headers=None):
    if ctx is None:
        ctx, headers = make_es_client()
    url = f"{ES_HOST}{path}"
    data = json.dumps(body).encode() if body else None
    m = method or ("POST" if body else "GET")
    req = urllib.request.Request(url, data=data, headers=headers, method=m)
    resp = urllib.request.urlopen(req, context=ctx)
    return json.loads(resp.read())

def load_from_elasticsearch(max_docs=100_000):
    ctx, headers = make_es_client()
    all_needed = (SHARED_FEATURES
                  + [f for feats in EXPERT_FEATURES.values() for f in feats]
                  + ["log_source", "composite_score", "priority_label"])
    all_needed = list(dict.fromkeys(all_needed))
    query = {
        "size": 5000,
        "query": {"exists": {"field": "ml.log_source"}},
        "_source": ["ml." + f for f in all_needed],
    }
    data = es_request(f"/{ES_INDEX_READ}/_search?scroll=2m", query,
                      ctx=ctx, headers=headers)
    scroll_id = data["_scroll_id"]
    rows = []

    def extract(d):
        r = []
        for hit in d["hits"]["hits"]:
            ml = hit.get("_source", {}).get("ml", {})
            if ml:
                ml["_id"] = hit["_id"]
                r.append(ml)
        return r

    rows += extract(data)
    page = 2
    while len(rows) < max_docs:
        data = es_request("/_search/scroll",
                          {"scroll": "2m", "scroll_id": scroll_id},
                          ctx=ctx, headers=headers)
        new = extract(data)
        if not new: break
        scroll_id = data["_scroll_id"]
        rows += new
        print(f"  Page {page}: +{len(new)} (total {len(rows)})")
        page += 1

    print(f"  Chargement: {len(rows)} events")
    return pd.DataFrame(rows)


# ===========================================================================
# SECTION 4 — ENTRAÎNEMENT
# ===========================================================================

def train(model, data_by_source, epochs=EPOCHS, lr=LR):
    """
    data_by_source : dict {src_name: (X_sh_normal, X_ex_normal)}
    WeightedRandomSampler équilibre automatiquement les sources.
    """
    # Construire dataset unifié avec tag source
    all_sh, all_ex_padded, all_src_idx = [], [], []
    max_expert_dim = max(EXPERT_DIMS.values())

    src_to_idx = {s: i for i, s in enumerate(SOURCES)}

    for src in SOURCES:
        if src not in data_by_source:
            continue
        X_sh, X_ex = data_by_source[src]
        n = len(X_sh)
        # Padding des features expert à la dimension max (pour le collate)
        pad = np.zeros((n, max_expert_dim), dtype=np.float32)
        pad[:, :X_ex.shape[1]] = X_ex
        all_sh.append(X_sh)
        all_ex_padded.append(pad)
        all_src_idx += [src_to_idx[src]] * n

    X_sh_all  = np.vstack(all_sh)
    X_ex_all  = np.vstack(all_ex_padded)
    src_idx   = np.array(all_src_idx)

    # WeightedRandomSampler — équilibre les sources
    counts  = np.bincount(src_idx, minlength=len(SOURCES)).astype(float)
    counts  = np.maximum(counts, 1)
    weights = 1.0 / counts[src_idx]
    sampler = WeightedRandomSampler(
        torch.DoubleTensor(weights),
        num_samples=len(weights),
        replacement=True
    )

    dataset = TensorDataset(
        torch.FloatTensor(X_sh_all),
        torch.FloatTensor(X_ex_all),
        torch.LongTensor(src_idx)
    )
    loader = DataLoader(dataset, batch_size=BATCH_SIZE,
                        sampler=sampler, num_workers=0)

    opt  = torch.optim.Adam(model.parameters(), lr=lr,
                            weight_decay=WEIGHT_DECAY)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)
    idx_to_src = {i: s for i, s in enumerate(SOURCES)}
    history = []
    best_loss, best_state = float("inf"), None

    model.train()
    for epoch in range(epochs):
        epoch_loss = 0.0
        for x_sh, x_ex_pad, s_idx in loader:
            x_sh = x_sh.to(DEVICE)
            opt.zero_grad()
            batch_loss = torch.tensor(0.0, device=DEVICE)

            # Traiter chaque source séparément dans le batch
            for src_id, src_name in idx_to_src.items():
                mask = (s_idx == src_id)
                if mask.sum() == 0:
                    continue
                expert_dim = EXPERT_DIMS[src_name]
                x_sh_s = x_sh[mask]
                x_ex_s = x_ex_pad[mask, :expert_dim].to(DEVICE)

                xsh_hat, xex_hat, _ = model(x_sh_s, x_ex_s, src_name)
                loss_sh = nn.MSELoss()(xsh_hat, x_sh_s)
                loss_ex = nn.MSELoss()(xex_hat, x_ex_s)
                batch_loss = batch_loss + 0.4 * loss_sh + 0.6 * loss_ex

            batch_loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            epoch_loss += batch_loss.item()

        avg = epoch_loss / len(loader)
        history.append(avg)
        sched.step()

        if avg < best_loss:
            best_loss  = avg
            best_state = {k: v.clone() for k, v in model.state_dict().items()}

        if epoch % 15 == 0 or epoch == epochs - 1:
            marker = " ← best" if avg == best_loss else ""
            print(f"  Epoch {epoch+1:3d}/{epochs} | loss={avg:.5f}{marker}")

    model.load_state_dict(best_state)
    print(f"  Meilleure loss : {best_loss:.5f}")
    return model, history


# ===========================================================================
# SECTION 5 — CALIBRATION
# ===========================================================================

def calibrate_thresholds(model, data_by_source):
    model.eval()
    thresholds = {}
    print(f"\n  Calibration seuils (P{ANOMALY_PCT}) :")
    for src in SOURCES:
        if src not in data_by_source:
            continue
        X_sh, X_ex = data_by_source[src]
        mse = model.reconstruction_error(
            torch.FloatTensor(X_sh).to(DEVICE),
            torch.FloatTensor(X_ex).to(DEVICE),
            src
        )
        clip = np.percentile(mse, 99.5)
        thr  = float(np.percentile(mse[mse < clip], ANOMALY_PCT))
        thresholds[src] = thr
        print(f"  {src:8s}: n={len(mse):5d} | "
              f"médiane={np.median(mse):.5f} | seuil={thr:.5f}")
    return thresholds


# ===========================================================================
# SECTION 6 — GROUND TRUTH
# ===========================================================================

def build_ground_truth(df):
    def col(c):
        return pd.to_numeric(df.get(c, 0), errors="coerce").fillna(0).astype(int)

    # Indicateurs directs (features conservées dans l'expert auditd)
    attack_flags = (
        (col("aud_reverse_shell")        == 1) |
        (col("aud_process_injection")    == 1) |
        (col("aud_credential_access")    == 1) |
        (col("aud_ssh_key_implant")      == 1) |
        (col("aud_exfiltration")         == 1) |
        (col("aud_log_delete")           == 1) |
        (col("cross_bruteforce_success") == 1) |
        (col("cross_ssh_then_sudo")      == 1) |
        (col("auth_is_brute_force")      == 1) |
        (col("auth_is_stuffing")         == 1)
    )
    # Fallback : composite_score élevé
    score = pd.to_numeric(df.get("composite_score", 0), errors="coerce").fillna(0)
    return (attack_flags | (score >= 6)).astype(int)


# ===========================================================================
# SECTION 7 — ÉVALUATION
# ===========================================================================

def evaluate(model, dfs_by_source, scalers, thresholds):
    model.eval()
    os.makedirs(PLOTS_DIR, exist_ok=True)
    all_results = []

    for src in SOURCES:
        if src not in dfs_by_source:
            continue
        df = dfs_by_source[src]
        sc_sh, sc_ex = scalers[src]

        X_sh, X_ex, _, _ = preprocess_source(
            df, src, sc_sh, sc_ex, fit=False
        )
        mse = model.reconstruction_error(
            torch.FloatTensor(X_sh).to(DEVICE),
            torch.FloatTensor(X_ex).to(DEVICE),
            src
        )
        thr = thresholds.get(src, 0.5)
        p99 = np.percentile(mse, 99) + 1e-9
        score_norm = np.clip(np.log1p(mse) / np.log1p(p99), 0, 1)

        df = df.copy()
        df["ae_mse_error"]     = np.round(mse, 6)
        df["ae_anomaly_score"] = np.round(score_norm, 4)
        df["ae_is_anomaly"]    = (mse > thr).astype(int)
        df["ae_threshold"]     = thr
        all_results.append(df)

        n_ano = (mse > thr).sum()
        print(f"  {src:8s}: {n_ano:4d}/{len(df):6d} anomalies "
              f"({n_ano/len(df)*100:.1f}%)  seuil={thr:.5f}")

    df_all = pd.concat(all_results, ignore_index=True)

    y_true  = build_ground_truth(df_all)
    y_pred  = df_all["ae_is_anomaly"].values
    y_score = df_all["ae_mse_error"].values

    print(f"\n  Ground truth positifs : {y_true.sum()}")
    if y_true.sum() > 0:
        auc = roc_auc_score(y_true, y_score)
        apr = average_precision_score(y_true, y_score)
        f1  = f1_score(y_true, y_pred, zero_division=0)
        print(f"  AUC-ROC={auc:.4f}  AUC-PR={apr:.4f}  F1={f1:.4f}")
        _plot_roc(y_true, y_score, auc)

    _plot_loss_placeholder()  # sera rempli après train
    return df_all

def _plot_roc(y_true, y_score, auc):
    from sklearn.metrics import roc_curve
    fpr, tpr, _ = roc_curve(y_true, y_score)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(fpr, tpr, lw=2, label=f"AUC={auc:.4f}")
    ax.plot([0,1],[0,1],"k--",lw=1)
    ax.set_xlabel("FPR"); ax.set_ylabel("TPR")
    ax.legend(); ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/roc.png", dpi=150)
    plt.close()

def _plot_loss_placeholder():
    pass

def plot_loss(history):
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot(history, lw=1.5)
    ax.set_xlabel("Epoch"); ax.set_ylabel("Loss")
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/loss.png", dpi=150)
    plt.close()


# ===========================================================================
# SECTION 8 — ÉCRITURE ES
# ===========================================================================

def write_to_elasticsearch(df_result, thresholds, batch_size=500):
    ctx, headers = make_es_client()
    anomalies = df_result[df_result["ae_is_anomaly"] == 1].copy()
    if len(anomalies) == 0:
        print("  Aucune anomalie à écrire")
        return

    gt = build_ground_truth(anomalies)
    print(f"  Écriture {len(anomalies)} anomalies "
          f"(dont {gt.sum()} vrais positifs)...")

    bulk = ""
    count = 0
    for i, (_, row) in enumerate(anomalies.iterrows()):
        src = str(row.get("log_source", "unknown"))
        doc = {
            "@timestamp":       datetime.now(timezone.utc).isoformat(),
            "source_id":        str(row.get("_id", "unknown")),
            "log_source":       src,
            "ae_mse_error":     safe_float(row.get("ae_mse_error", 0)),
            "ae_anomaly_score": safe_float(row.get("ae_anomaly_score", 0)),
            "ae_is_anomaly":    1,
            "ae_threshold":     safe_float(row.get("ae_threshold", 0.5)),
            "composite_score":  safe_int(row.get("composite_score", 0)),
            "priority_label":   str(row.get("priority_label", "unknown")),
            "ground_truth":     int(gt.iloc[i]) if i < len(gt) else 0,
        }
        bulk  += json.dumps({"index": {"_index": ES_INDEX_WRITE}}) + "\n"
        bulk  += json.dumps(doc) + "\n"
        count += 1
        if count % batch_size == 0:
            req = urllib.request.Request(
                f"{ES_HOST}/_bulk", data=bulk.encode(),
                headers=headers, method="POST")
            urllib.request.urlopen(req, context=ctx)
            print(f"    {count} docs écrits")
            bulk = ""
    if bulk:
        req = urllib.request.Request(
            f"{ES_HOST}/_bulk", data=bulk.encode(),
            headers=headers, method="POST")
        urllib.request.urlopen(req, context=ctx)
    print(f"  {count} anomalies écrites dans {ES_INDEX_WRITE}")


# ===========================================================================
# SECTION 9 — INFÉRENCE TEMPS RÉEL
# ===========================================================================

def predict_single_event(event_dict, model, scalers, thresholds):
    """
    event_dict : champs ml.* d'un event ES
    Retourne dict avec ae_is_anomaly, ae_mse_error, ae_anomaly_score
    """
    src = str(event_dict.get("log_source", "unknown"))
    if src not in SOURCES:
        return {"ae_is_anomaly": 0, "ae_mse_error": 0.0,
                "ae_anomaly_score": 0.0, "ae_source": src}

    df = pd.DataFrame([event_dict])
    sc_sh, sc_ex = scalers[src]
    X_sh, X_ex, _, _ = preprocess_source(df, src, sc_sh, sc_ex, fit=False)

    mse = model.reconstruction_error(
        torch.FloatTensor(X_sh).to(DEVICE),
        torch.FloatTensor(X_ex).to(DEVICE),
        src
    )[0]

    thr   = thresholds.get(src, 0.5)
    p99   = thr * 3 + 1e-9
    score = float(np.clip(np.log1p(mse) / np.log1p(p99), 0, 1))

    return {
        "ae_is_anomaly":    1 if mse > thr else 0,
        "ae_mse_error":     round(float(mse), 6),
        "ae_anomaly_score": round(score, 4),
        "ae_threshold":     round(thr, 6),
        "ae_source":        src,
    }


# ===========================================================================
# MAIN
# ===========================================================================

if __name__ == "__main__":
    print("=" * 58)
    print("  MIXTURE-OF-EXPERTS AUTOENCODER IDS")
    print(f"  Device: {DEVICE}")
    print("=" * 58)

    # 1. Chargement
    print("\n[1/6] Chargement Elasticsearch...")
    df_raw = load_from_elasticsearch()
    if len(df_raw) == 0:
        print("ERREUR: index vide"); exit(1)

    print("\n  Distribution sources:")
    for src, cnt in df_raw.get("log_source",
                                pd.Series()).value_counts().items():
        print(f"    {src:10s}: {cnt:6d}")

    # 2. Séparation par source + prétraitement
    print("\n[2/6] Prétraitement par source...")
    dfs_by_source   = {}
    data_normal     = {}   # pour entraînement
    data_all        = {}   # pour évaluation
    scalers         = {}

    for src in SOURCES:
        mask_src = df_raw.get("log_source",
                               pd.Series()) == src
        df_src = df_raw[mask_src].reset_index(drop=True)
        if len(df_src) == 0:
            print(f"  {src}: aucun event"); continue

        dfs_by_source[src] = df_src

        # Masque normal
        score_col = pd.to_numeric(
            df_src.get("composite_score", 0), errors="coerce").fillna(0)
        normal_mask = score_col < NORMAL_THR

        print(f"  {src}: {len(df_src)} events "
              f"({normal_mask.sum()} normaux / "
              f"{(~normal_mask).sum()} anormaux)")

        # Fit sur les normaux
        df_normal = df_src[normal_mask].reset_index(drop=True)
        if len(df_normal) < 100:
            print(f"  ATTENTION: {src} a moins de 100 events normaux")

        X_sh_n, X_ex_n, sc_sh, sc_ex = preprocess_source(
            df_normal, src, fit=True
        )
        scalers[src]      = (sc_sh, sc_ex)
        data_normal[src]  = (X_sh_n, X_ex_n)

        # Transform sur tous les events (pour évaluation)
        X_sh_a, X_ex_a, _, _ = preprocess_source(
            df_src, src, sc_sh, sc_ex, fit=False
        )
        data_all[src] = (X_sh_a, X_ex_a)

    # 3. Modèle
    print("\n[3/6] Création du modèle MoE-AE...")
    model = MoEAutoencoder(SHARED_DIM, EXPERT_DIMS, LATENT_DIM).to(DEVICE)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"  Paramètres: {total_params:,}")
    print(f"  shared_dim={SHARED_DIM}  "
          + "  ".join(f"expert_{s}={d}"
                      for s, d in EXPERT_DIMS.items()))

    # 4. Entraînement
    print("\n[4/6] Entraînement...")
    model, history = train(model, data_normal)
    torch.save(model.state_dict(), MODEL_PATH)
    joblib.dump(scalers, SCALERS_PATH)
    joblib.dump(thresholds := {}, THRESH_PATH)
    plot_loss(history)
    print(f"  Modèle sauvegardé: {MODEL_PATH}")

    # 5. Calibration
    print("\n[5/6] Calibration des seuils...")
    thresholds = calibrate_thresholds(model, data_normal)
    joblib.dump(thresholds, THRESH_PATH)

    # 6. Évaluation + écriture ES
    print("\n[6/6] Évaluation...")
    df_result = evaluate(model, dfs_by_source, scalers, thresholds)
    write_to_elasticsearch(df_result, thresholds)

    print("\n" + "=" * 58)
    print("  TERMINÉ")
    print("=" * 58)
    print(f"""
  Fichiers: {MODEL_PATH}  {SCALERS_PATH}  {THRESH_PATH}

  Inférence temps réel:
    model = MoEAutoencoder(SHARED_DIM={SHARED_DIM},
                           EXPERT_DIMS={EXPERT_DIMS},
                           LATENT_DIM={LATENT_DIM})
    model.load_state_dict(torch.load("{MODEL_PATH}"))
    scalers    = joblib.load("{SCALERS_PATH}")
    thresholds = joblib.load("{THRESH_PATH}")

    result = predict_single_event(event_ml_dict, model,
                                  scalers, thresholds)
""")