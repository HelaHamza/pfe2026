"""
=============================================================================
MoE-AE IDS — PIPELINE COMPLET (version corrigée — 4 risques résolus)
=============================================================================

CORRECTIONS APPLIQUÉES :
  RISQUE 1 : Agrégats Logstash perdus au redémarrage
             → Persistance Redis des compteurs fenêtrés
             → Fallback silencieux si Redis indisponible

  RISQUE 2 : Pondération 35/65 figée
             → Paramètre alpha appris par source (nn.ParameterDict)
             → Initialisé à logit(0.35) pour partir du même point

  RISQUE 3 : Seuil P99 unique par source
             → 3 tranches horaires × 3 sources = 9 seuils adaptatifs
             → business (9h-18h) | night (22h-5h) | other

  RISQUE 4 : Faux normaux dans le training set
             → Nettoyage itératif : 2 passes d'entraînement
             → Passe 1 → identifie top 2% MSE → exclut → Passe 2

ORDRE D'EXÉCUTION :
  ÉTAPE PRÉALABLE :
    python ids_inject_test_logs.py   → ids-test-logs
    python ids_inject_normal_logs.py → ids-train-normal (optionnel)

  CE SCRIPT :
    [1] Chargement logs réels + synthétiques normaux
    [2] Chargement jeu de TEST
    [3] Split Train / Val (75/25)
    [4] Prétraitement (StandardScaler)
    [5] Création modèle MoEAutoencoderV2 (alpha appris — risque 2)
    [6] Entraînement itératif avec nettoyage (risque 4)
    [7] Calibration seuils adaptatifs par tranche horaire (risque 3)
    [8] Évaluation complète (7 métriques)
    [9] Écriture ES anomalies

=============================================================================
"""
from datetime import datetime, timezone
import sys, json, ssl, urllib.request, base64, os, time, warnings, math
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset, WeightedRandomSampler
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    roc_auc_score, average_precision_score,
    f1_score, precision_score, recall_score,
    confusion_matrix, roc_curve, precision_recall_curve
)
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from dotenv import load_dotenv

warnings.filterwarnings("ignore")
np.random.seed(42)
torch.manual_seed(42)
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")



# =============================================================================
# SECTION A — CONFIGURATION
# =============================================================================
load_dotenv()

ES_HOST         = "https://localhost:9200"
ES_USER         = "elastic"
ES_PASS = os.getenv("ELASTIC_PWD")
ES_INDEX_TRAIN  = "filebeat-logs-*,auditbeat-*"
ES_INDEX_SYNTH  = "ids-train-normal"        # logs normaux synthétiques certifiés
ES_INDEX_TEST   = "test-ml-logs"
ES_INDEX_WRITE  = "ml-autoencoder-scores"

MODEL_PATH   = "model_moe_ae.pt"
SCALERS_PATH = "moe_scalers.pkl" #
THRESH_PATH  = "moe_thresholds.pkl"
REPORT_PATH  = "evaluation_report.json"
PLOTS_DIR    = "moe_plots"

SOURCES      = ["syslog", "auth", "auditd"]

LATENT_DIM   = 16
BATCH_SIZE   = 256
EPOCHS       = 200
LR           = 1e-3
WEIGHT_DECAY = 1e-5
PATIENCE     = 25

TRAIN_RATIO  = 0.75
VAL_RATIO    = 0.25

N_BOOTSTRAP  = 100
BOOTSTRAP_PCT= 0.70
FLOOR_THRESHOLDS = {
    "auditd": 0.035,
    "auth":   0.80,
    "syslog": 0.063,
}


# RISQUE 4 — % de logs exclus comme potentiels faux normaux
CLEAN_PCT    = 2.0 # top 2% MSE exclus après première passe d'entraînement
CLEAN_PCT_BY_SOURCE = {
    "syslog": 2.0,
    "auth":   2.0,
    "auditd": 5.0,
}
# Section A — après ANOMALY_PCT = 99 :
ANOMALY_PCT = 99 # pour le calcul des seuils, on prend le percentile juste en dessous du clip à 99.5% pour éviter les outliers extrêmes

ANOMALY_PCT_BY_SOURCE = {
    "syslog": 99,
    "auth":   97,
    "auditd": 99.8,
}
# RISQUE 1 — Configuration Redis
REDIS_HOST   = "localhost"
REDIS_PORT   = 6379
REDIS_DB     = 0
REDIS_PASS   = None   # None si pas de mot de passe


# =============================================================================
# SECTION B — FEATURES
# =============================================================================

SHARED_FEATURES = [
    "hour_of_day", "day_of_week", "is_off_hours", "is_night",
    "is_weekend", "is_business", "hour_sin", "hour_cos",
    "msg_length_log", "msg_word_count", "msg_has_ip", "msg_has_base64",
    "msg_has_url", "msg_has_pipe", "is_root", "user_sensitivity",
    "delta_time_log", "log_source_encoded",
]
SHARED_DIM = len(SHARED_FEATURES)  # 18

EXPERT_FEATURES = {
    "auth": [
        "auth_is_root", "auth_ip_is_external", "auth_severity",
        "auth_sev_norm", "auth_user_sensitivity", "auth_known_country",
        "geo_distance", "auth_user_created", "auth_user_deleted",
        "auth_sudo_to_root", "auth_passwd_changed", "auth_pam_open",
        "auth_pam_close", "auth_fail_count_5m", "auth_fail_window_10m",
        "auth_ok_count_5m", "auth_fail_ratio", "auth_users_tried",
        "unique_users_per_ip", "auth_is_brute_force",
        "auth_is_slow_bruteforce", "auth_is_user_enum", "auth_is_stuffing",
        "session_duration_log", "cross_ssh_then_sudo",
        "cross_bruteforce_success", "freq_spike_ratio", "event_count_ip",
        "unique_hosts_accessed", "is_lateral_movement",
    ],
    "syslog": [
        "sys_oom_kill", "sys_module_load", "sys_cron_new_job",
        "sys_firewall_change", "sys_service_crash_loop", "sys_msg_length_log",
        "sys_lateral_ssh", "sys_new_service", "sys_log_tamper",
        "sys_high_cpu_process", "freq_spike_ratio", "freq_spike_ratio_5m",
        "event_count_ip", "event_count_1m_ip", "event_count_5m_ip",
        "cross_multi_source", "is_lateral_movement",
    ],
    "auditd": [
        "aud_severity", "aud_sev_norm", "aud_ptrace", "aud_process_injection",
        "aud_log_tamper", "aud_cmd_entropy", "aud_cmd_length_log",
        "aud_cmd_is_obfuscated", "aud_arg_count", "payload_size_log",
        "aud_reverse_shell", "aud_cron_backdoor", "aud_suid_abuse",
        "aud_ld_hijack", "aud_credential_access", "aud_ssh_key_implant",
        "aud_cryptominer", "aud_log_delete", "aud_network_scan",
        "aud_exfiltration", "aud_suspicious_combo", "delta_time_log",
        "event_count_ip",
    ],
}
EXPERT_DIMS = {s: len(f) for s, f in EXPERT_FEATURES.items()}

def sanitize_for_json(obj):
    """
    Parcourt récursivement un dict/list/valeur et remplace :
        float NaN  → None  (null JSON)
        float +Inf → None
        float -Inf → None
        numpy scalars → types Python natifs
 
    Elasticsearch rejette 'NaN' car c'est un token non standard JSON.
    None est sérialisé en null, accepté partout.
    """
    if isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_for_json(v) for v in obj]
    # numpy scalars → Python natifs
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        obj = float(obj)
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return None
    return obj
# =============================================================================
# SECTION C — ARCHITECTURE MoE-AE  (RISQUE 2 : alpha appris)
# =============================================================================

def make_encoder(input_dim: int, latent_dim: int) -> nn.Sequential:
    """
    Construit un encodeur MLP à 3 couches.

    Rôle : compresser un vecteur de features (dimension input_dim)
    en une représentation latente compacte (dimension latent_dim).

    Architecture :
        input_dim → hidden → hidden//2 → latent_dim
        Chaque couche : Linear → BatchNorm → GELU → Dropout

    Pourquoi GELU ?
        GELU (Gaussian Error Linear Unit) donne de meilleurs résultats
        que ReLU sur des distributions log-normales comme nos features
        de logs. Il est différentiable partout et traite mieux les
        petites valeurs négatives.

    Pourquoi BatchNorm ?
        Normalise les activations entre les couches → training plus
        stable, learning rate plus élevé possible.

    Args:
        input_dim  : nombre de features en entrée
        latent_dim : taille de la représentation compressée

    Returns:
        nn.Sequential prêt à être entraîné
    """
    hidden = max(input_dim * 2, 64)
    return nn.Sequential(
        nn.Linear(input_dim, hidden),
        nn.BatchNorm1d(hidden), nn.GELU(), nn.Dropout(0.15),
        nn.Linear(hidden, hidden // 2),
        nn.BatchNorm1d(hidden // 2), nn.GELU(), nn.Dropout(0.10),
        nn.Linear(hidden // 2, latent_dim),
    )

def make_decoder(latent_dim: int, output_dim: int) -> nn.Sequential:
    """
      Construit un décodeur MLP symétrique à l'encodeur.

    Rôle : reconstruire le vecteur de features original à partir
    de la représentation latente. L'erreur de reconstruction mesure
    l'anomalie : un log normal sera bien reconstruit (erreur faible),
    un log anormal sera mal reconstruit (erreur élevée).

    Architecture (symétrie inversée de l'encodeur) :
        latent_dim → hidden//2 → hidden → output_dim

    Args:
        latent_dim : taille de la représentation latente en entrée
        output_dim : nombre de features à reconstruire

    Returns:
        nn.Sequential prêt à être entraîné
    """
    hidden = max(output_dim * 2, 64)
    return nn.Sequential(
        nn.Linear(latent_dim, hidden // 2),
        nn.BatchNorm1d(hidden // 2), nn.GELU(), nn.Dropout(0.10),
        nn.Linear(hidden // 2, hidden),
        nn.BatchNorm1d(hidden), nn.GELU(), nn.Dropout(0.15),
        nn.Linear(hidden, output_dim),
    )


class MoEAutoencoder(nn.Module):
    """


    Principe général d'un autoencoder pour l'IDS :
        1. Entraîner uniquement sur des logs NORMAUX
        2. Le modèle apprend à reconstruire les patterns normaux
        3. À l'inférence, un log normal → erreur de reconstruction faible
           Un log anormal (attaque) → erreur élevée car pattern inconnu
        4. Si erreur > seuil calibré → ANOMALIE détectée

    Architecture Mixture-of-Experts :
        • Un encodeur/décodeur PARTAGÉ pour les features communes
          (heure, jour, longueur message…)
        • Un encodeur/décodeur EXPERT par source (auth, syslog, auditd)
          pour les features spécifiques à chaque type de log

    Fusion dans l'espace latent :
        z = z_shared + z_expert
        Addition simple : les deux représentations s'enrichissent
        mutuellement. z_shared capte les patterns temporels communs,
        z_expert capte les signatures spécifiques à la source.

    MoE-Autoencoder avec pondération alpha APPRISE par source.


    RISQUE 2 corrigé :
        self.alphas : nn.ParameterDict — un scalaire par source.
        alpha = sigmoid(raw) est contraint dans [0,1].
        Initialisé à logit(0.35) ≈ -0.619 → même point de départ
        que l'ancienne pondération manuelle 35/65.

        Après entraînement :
            alpha → fraction attribuée aux features SHARED
            1-alpha → fraction attribuée aux features EXPERT

        Pour inspecter :
            model.get_alphas()
            # → {"syslog": 0.31, "auth": 0.28, "auditd": 0.40}
    """

    def __init__(self, shared_dim: int, expert_dims: dict,
                 latent_dim: int = LATENT_DIM):
        super().__init__()
        self.shared_dim  = shared_dim
        self.expert_dims = expert_dims
        self.latent_dim  = latent_dim

        self.shared_encoder = make_encoder(shared_dim, latent_dim)
        self.shared_decoder = make_decoder(latent_dim, shared_dim)

        self.expert_encoders = nn.ModuleDict({
            src: make_encoder(dim, latent_dim)
            for src, dim in expert_dims.items()
        })
        self.expert_decoders = nn.ModuleDict({
            src: make_decoder(latent_dim, dim)
            for src, dim in expert_dims.items()
        
        })
                # Alphas : initialisés à 0.35, contraints dans [0.10, 0.90]
        self._alpha_raw = nn.ParameterDict({
            src: nn.Parameter(torch.tensor(0.35))
            for src in expert_dims
        })

        # RISQUE 2 — alpha appris par source
        # logit(0.35) = log(0.35/0.65) ≈ -0.619
        # sigmoid(-0.619) ≈ 0.35 → on part du même point que la version manuelle


    def get_alpha(self, src):
        raw = self._alpha_raw[src]
        return 0.10 + 0.80 * torch.sigmoid(raw)

    def get_alphas(self):
        """Retourne un dict {src: alpha_value} pour tous les experts."""
        return {
            src: round(self.get_alpha(src).item(), 3)
            for src in self._alpha_raw
    }

    def forward(self, x_shared, x_expert, src):
        alpha = self.get_alpha(src)

        z_shared = self.shared_encoder(x_shared)
        z_expert = self.expert_encoders[src](x_expert)

        # Fusion contrainte : alpha ∈ [0.10, 0.90] garanti
        z = alpha * z_shared + (1 - alpha) * z_expert

        recon_shared = self.shared_decoder(z)
        recon_expert = self.expert_decoders[src](z)

        return recon_shared, recon_expert, alpha
    def reconstruction_error(self, x_shared: torch.Tensor,
                             x_expert: torch.Tensor,
                             src_name: str) -> np.ndarray:
        """
        MSE pondérée par alpha appris (risque 2 corrigé).
        alpha = sigmoid(self.alphas[src]) — appris, pas fixé manuellement.
        """
        self.eval()
        with torch.no_grad():
            sh_hat, ex_hat, _ = self.forward(x_shared, x_expert, src_name)
            mse_sh = ((x_shared - sh_hat) ** 2).mean(dim=1)
            mse_ex = ((x_expert - ex_hat) ** 2).mean(dim=1)
            alpha  = torch.sigmoid(self._alpha_raw[src_name])
        return (alpha * mse_sh + (1 - alpha) * mse_ex).cpu().numpy()

    def weighted_huber_loss(self, sh_hat, x_sh, ex_hat, x_ex,
                            src_name: str) -> torch.Tensor:
        """Huber loss pondérée par alpha — utilisée dans train()."""
        alpha = torch.sigmoid(self._alpha_raw[src_name])
        return (alpha       * F.huber_loss(sh_hat, x_sh, delta=0.5)
              + (1 - alpha) * F.huber_loss(ex_hat, x_ex, delta=0.5))

    


# =============================================================================
# SECTION D — ELASTICSEARCH
# =============================================================================

def make_es_client():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    token   = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Basic {token}",
    }
    return ctx, headers


def es_request(path: str, body=None, method: str = None,
               ctx=None, headers=None):
    if ctx is None:
        ctx, headers = make_es_client()
    url  = f"{ES_HOST}{path}"
    data = json.dumps(body).encode() if body else None
    m    = method or ("POST" if body else "GET")
    req  = urllib.request.Request(url, data=data, headers=headers, method=m)
    return json.loads(urllib.request.urlopen(req, context=ctx).read())


def load_training_data(max_docs: int = 150_000) -> pd.DataFrame:
    """Charge les logs RÉELS depuis filebeat-logs-* et auditbeat-*."""
    ctx, headers = make_es_client()
    all_fields = list(dict.fromkeys(
        SHARED_FEATURES
        + [f for fl in EXPERT_FEATURES.values() for f in fl]
        + ["log_source", "is_normal_candidate", "normal_reject_reason",
           "composite_score", "priority_label"]
    ))
    query = {
        "size": 5000,
        "query": {"exists": {"field": "ml.log_source"}},
        "_source": ["ml." + f for f in all_fields],
    }
    data      = es_request(f"/{ES_INDEX_TRAIN}/_search?scroll=2m",
                           query, ctx=ctx, headers=headers)
    scroll_id = data["_scroll_id"]
    rows      = []

    def extract(d):
        out = []
        for hit in d["hits"]["hits"]:
            ml = hit.get("_source", {}).get("ml", {})
            if ml:
                ml["_id"] = hit["_id"]
                out.append(ml)
        return out

    rows += extract(data)
    page  = 2
    while len(rows) < max_docs:
        data = es_request("/_search/scroll",
                          {"scroll": "2m", "scroll_id": scroll_id},
                          ctx=ctx, headers=headers)
        new = extract(data)
        if not new:
            break
        scroll_id = data["_scroll_id"]
        rows     += new
        if page % 5 == 0:
            print(f"    Page {page}: {len(rows)} logs")
        page += 1

    print(f"  Logs réels chargés : {len(rows)}")
    return pd.DataFrame(rows)


def load_synthetic_normal() -> pd.DataFrame:
    """
    Charge les logs normaux synthétiques certifiés depuis ids-train-normal.
    Créés par ids_inject_normal_logs.py — ground_truth=0 garanti.
    Retourne un DataFrame vide si l'index n'existe pas.
    """
    ctx, headers = make_es_client()
    try:
        es_request(f"/{ES_INDEX_SYNTH}", method="GET",
                   ctx=ctx, headers=headers)
    except Exception:
        print(f"  Index {ES_INDEX_SYNTH} absent — entraînement sur réels seuls")
        return pd.DataFrame()

    ml_fields = list(dict.fromkeys(
        SHARED_FEATURES
        + [f for fl in EXPERT_FEATURES.values() for f in fl]
        + ["log_source"]
    ))
    query = {
        "size": 5000,
        "query": {"match_all": {}},
        "_source": ["log_source"] + ["ml." + f for f in ml_fields],
    }
    data      = es_request(f"/{ES_INDEX_SYNTH}/_search?scroll=2m",
                           query, ctx=ctx, headers=headers)
    scroll_id = data["_scroll_id"]
    rows      = []

    def extract(d):
        out = []
        for hit in d["hits"]["hits"]:
            src_doc = hit.get("_source", {})
            ml      = src_doc.get("ml", {})
            ml["log_source"]          = src_doc.get(
                "log_source", ml.get("log_source", "unknown"))
            ml["is_normal_candidate"] = 1   # certifié — pas de masque nécessaire
            ml["_id"]                 = hit["_id"]
            out.append(ml)
        return out

    rows += extract(data)
    while True:
        data = es_request("/_search/scroll",
                          {"scroll": "2m", "scroll_id": scroll_id},
                          ctx=ctx, headers=headers)
        new = extract(data)
        if not new:
            break
        scroll_id = data["_scroll_id"]
        rows     += new

    df = pd.DataFrame(rows)
    print(f"  Logs synthétiques chargés : {len(df)}")
    for src in SOURCES:
        n = (df["log_source"] == src).sum()
        print(f"    {src:8s}: {n:6d}")
    return df


def merge_training_data(df_real: pd.DataFrame,
                        df_synth: pd.DataFrame) -> pd.DataFrame:
    """
    Fusionne logs réels filtrés + synthétiques certifiés.
    Ratio cible : 70-80% réels / 20-30% synthétiques.
    """
    if df_synth.empty:
        return df_real

    df_real  = df_real.copy();  df_real["data_source"]  = "real"
    df_synth = df_synth.copy(); df_synth["data_source"] = "synthetic"
    merged   = pd.concat([df_real, df_synth], ignore_index=True)
    pct      = round(len(df_synth) / len(merged) * 100, 1)
    print(f"  Fusion : {len(df_real):,} réels + {len(df_synth):,} synthétiques "
          f"= {len(merged):,} total ({pct}% synthétiques)")
    return merged


def load_test_data() -> pd.DataFrame:
    """Charge le jeu de test depuis ids-test-logs."""
    ctx, headers = make_es_client()
    ml_fields = list(dict.fromkeys(
        SHARED_FEATURES
        + [f for fl in EXPERT_FEATURES.values() for f in fl]
        + ["log_source", "composite_score"]
    ))
    query = {
        "size": 5000,
        "query": {"match_all": {}},
        "_source": (["ground_truth", "attack_type", "log_source"]
                    + ["ml." + f for f in ml_fields]),
    }
    data      = es_request(f"/{ES_INDEX_TEST}/_search?scroll=2m",
                           query, ctx=ctx, headers=headers)
    scroll_id = data["_scroll_id"]
    rows      = []

    def extract_test(d):
        out = []
        for hit in d["hits"]["hits"]:
            src = hit.get("_source", {})
            ml  = src.get("ml", {})
            ml["ground_truth"] = int(src.get("ground_truth", 0))
            ml["attack_type"]  = str(src.get("attack_type", "normal"))
            ml["log_source"]   = str(src.get("log_source",
                                 ml.get("log_source", "unknown")))
            ml["_es_id"]       = hit["_id"]
            out.append(ml)
        return out

    rows += extract_test(data)
    while True:
        data = es_request("/_search/scroll",
                          {"scroll": "2m", "scroll_id": scroll_id},
                          ctx=ctx, headers=headers)
        new = extract_test(data)
        if not new:
            break
        scroll_id = data["_scroll_id"]
        rows     += new

    df = pd.DataFrame(rows)
    print(f"  Jeu de test : {len(df)} docs")
    print(f"    Normaux  : {(df['ground_truth']==0).sum()}")
    print(f"    Attaques : {(df['ground_truth']==1).sum()}")
    if "attack_type" in df.columns:
        for t, c in df[df["ground_truth"]==1]["attack_type"].value_counts().items():
            print(f"      {str(t):30s}: {c}")
    return df


# =============================================================================
# SECTION E — MASQUE NORMAL
# =============================================================================

def build_normal_mask(df: pd.DataFrame) -> pd.Series:
    """Identifie les logs normaux via is_normal_candidate (Logstash Sec.12)."""
    if "is_normal_candidate" in df.columns:
        mask = pd.to_numeric(df["is_normal_candidate"],
                             errors="coerce").fillna(0).astype(int) == 1
        print(f"  Masque Logstash : {mask.sum()} / {len(df)} "
              f"({mask.sum()/len(df)*100:.1f}%)")
        return mask

    print("  Recalcul masque Python (fallback)...")
    def col(c):
        return pd.to_numeric(df.get(c, 0), errors="coerce").fillna(0)

    c1 = col("composite_score") < 2
    c2 = (col("hour_of_day") >= 8) & (col("hour_of_day") <= 18)
    c3 = (col("day_of_week") >= 1) & (col("day_of_week") <= 5)
    FLAGS = [
        "aud_reverse_shell", "aud_process_injection", "aud_log_delete",
        "aud_credential_access", "aud_ssh_key_implant", "auth_is_brute_force",
        "auth_is_stuffing", "cross_bruteforce_success", "sys_log_tamper",
        "sys_module_load", "is_lateral_movement", "aud_suspicious_combo",
    ]
    c4 = pd.Series(True, index=df.index)
    for f in FLAGS:
        if f in df.columns:
            c4 = c4 & (col(f) == 0)
    mask = c1 & c2 & c3 & c4
    print(f"  Masque Python : {mask.sum()} / {len(df)}")
    return mask


# =============================================================================
# SECTION F — PRÉTRAITEMENT
# =============================================================================

def preprocess_source(df_src, src_name, scaler_sh=None, scaler_ex=None,
                      fit=True):
    """
    Extrait et normalise les features shared + expert pour une source.==> pour un log donné, on extrait les features communes et les features spécifiques à sa source, puis on les normalise avec StandardScaler.
    fit=True uniquement sur le split TRAIN (évite la fuite de données).
    """
    df = df_src.copy()

    def get_col(c):
        if c not in df.columns:
            return np.zeros(len(df), dtype=np.float32)
        return pd.to_numeric(df[c], errors="coerce").fillna(0).values

    X_sh = np.nan_to_num(
        np.stack([get_col(c) for c in SHARED_FEATURES], axis=1
                 ).astype(np.float32)
    )
    X_ex = np.nan_to_num(
        np.stack([get_col(c) for c in EXPERT_FEATURES[src_name]], axis=1
                 ).astype(np.float32)
    )
    if fit:
        scaler_sh = StandardScaler().fit(X_sh)
        scaler_ex = StandardScaler().fit(X_ex)
    return (scaler_sh.transform(X_sh).astype(np.float32),
            scaler_ex.transform(X_ex).astype(np.float32),
            scaler_sh, scaler_ex)


# =============================================================================
# SECTION G — ENTRAÎNEMENT (utilise weighted_huber_loss — risque 2)
# =============================================================================

def train(model, data_train, data_val, epochs=EPOCHS, lr=LR):
    """
    Entraîne le MoE-AE sur les logs normaux.

    Modifications vs version originale (risque 2) :
        La loss utilise model.weighted_huber_loss() qui pondère
        via alpha appris au lieu de la constante 0.35/0.65.
    """
    max_ex_dim = max(EXPERT_DIMS.values())
    src_to_idx = {s: i for i, s in enumerate(SOURCES)}
    idx_to_src = {i: s for i, s in enumerate(SOURCES)}

    def build_loader(data_dict, shuffle=True):
        all_sh, all_ex_pad, all_src_idx = [], [], []
        for src in SOURCES:
            if src not in data_dict:
                continue
            X_sh, X_ex = data_dict[src]
            pad = np.zeros((len(X_sh), max_ex_dim), dtype=np.float32)
            pad[:, :X_ex.shape[1]] = X_ex
            all_sh.append(X_sh)
            all_ex_pad.append(pad)
            all_src_idx += [src_to_idx[src]] * len(X_sh)

        X_sh_all = np.vstack(all_sh)
        X_ex_all = np.vstack(all_ex_pad)
        src_idx  = np.array(all_src_idx)
        dataset  = TensorDataset(torch.FloatTensor(X_sh_all),
                                 torch.FloatTensor(X_ex_all),
                                 torch.LongTensor(src_idx))
        if shuffle:
            counts  = np.maximum(
                np.bincount(src_idx, minlength=len(SOURCES)), 1
            ).astype(float)
            weights = 1.0 / counts[src_idx]
            sampler = WeightedRandomSampler(
                torch.DoubleTensor(weights), len(weights), replacement=True
            )
            return DataLoader(dataset, batch_size=BATCH_SIZE,
                              sampler=sampler, num_workers=0)
        return DataLoader(dataset, batch_size=BATCH_SIZE,
                          shuffle=False, num_workers=0)

    train_loader = build_loader(data_train, shuffle=True)
    val_loader   = build_loader(data_val,   shuffle=False)

    optimizer = torch.optim.AdamW(model.parameters(), lr=lr,
                                  weight_decay=WEIGHT_DECAY)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingWarmRestarts(
        optimizer, T_0=50, T_mult=2, eta_min=1e-5
    )
#les logs arrivent par batch puis on extraire les logs par type, deux barnches sont actif au meme temps , l'un pour les caractéristique commune et l'autre pour un type de log donnée
    def run_epoch(loader, train_mode):
        model.train() if train_mode else model.eval()
        total, nb = 0.0, 0
        ctx_mgr = torch.enable_grad() if train_mode else torch.no_grad()
        with ctx_mgr:
            for x_sh, x_ex_pad, s_idx in loader:
                x_sh = x_sh.to(DEVICE)
                if train_mode:
                    optimizer.zero_grad()
                batch_loss = torch.tensor(0.0, device=DEVICE)
                for sid, sname in idx_to_src.items(): # ce bloc de for permet d'extraire les logs d'une source précis puis faire l'ntrainement du modele sur ce type e log
                    mask = (s_idx == sid)
                    if mask.sum() == 0:
                        continue
                    edim   = EXPERT_DIMS[sname]
                    x_sh_s = x_sh[mask]
                    x_ex_s = x_ex_pad[mask, :edim].to(DEVICE)
                    sh_hat, ex_hat, _ = model(x_sh_s, x_ex_s, sname)
                    # RISQUE 2 — loss pondérée par alpha appris
                    loss = model.weighted_huber_loss(
                        sh_hat, x_sh_s, ex_hat, x_ex_s, sname
                    )
                    batch_loss = batch_loss + loss
                if train_mode:
                    batch_loss.backward()
                    nn.utils.clip_grad_norm_(model.parameters(), 0.5)
                    optimizer.step()
                total += batch_loss.item()
                nb    += 1
        return total / max(nb, 1)

    best_val_loss = float("inf")
    best_state    = None
    patience_cnt  = 0
    train_hist, val_hist = [], []

    print(f"\n  Splits :")
    for src in SOURCES:
        n_tr = len(data_train.get(src, ([],))[0])
        n_va = len(data_val.get(src,   ([],))[0])
        print(f"    {src:8s}: {n_tr:6d} train | {n_va:5d} val")

    t0 = time.time()
    for epoch in range(epochs):
        t_loss = run_epoch(train_loader, train_mode=True)
        v_loss = run_epoch(val_loader,   train_mode=False)
        scheduler.step()
        train_hist.append(t_loss)
        val_hist.append(v_loss)

        if v_loss < best_val_loss - 1e-5:
            best_val_loss = v_loss
            best_state    = {k: v.clone() for k, v in model.state_dict().items()}
            patience_cnt  = 0
            marker        = " ← best"
        else:
            patience_cnt += 1
            marker        = f" (patience {patience_cnt}/{PATIENCE})"

        if (epoch + 1) % 20 == 0 or epoch == 0:
            print(f"  Epoch {epoch+1:3d}/{epochs} | "
                  f"train={t_loss:.6f} | val={v_loss:.6f}{marker}")

        if patience_cnt >= PATIENCE:
            print(f"\n  Early stopping epoch {epoch+1}")
            break

    elapsed = time.time() - t0
    model.load_state_dict(best_state)
    print(f"  Durée : {elapsed:.1f}s | Best val : {best_val_loss:.6f}")
    return model, train_hist, val_hist, elapsed


# =============================================================================
# RISQUE 4 — NETTOYAGE ITÉRATIF DU TRAINING SET
# =============================================================================

def clean_training_set(model, data_train: dict,
                       data_val: dict) -> tuple:
    """
    Exclut les logs avec la MSE la plus élevée du training set.

    Ces logs ont une erreur de reconstruction anormalement haute
    malgré le masque is_normal_candidate → probablement des faux normaux.

    Processus :
        1. Calcule MSE sur tout le training set avec le modèle passe 1
        2. Exclut les CLEAN_PCT% de logs au-dessus du percentile
        3. Retourne les sets nettoyés + les indices gardés

    CLEAN_PCT = 2.0% par défaut (conservateur).

    Returns:
        data_train_clean : dict {src: (X_sh, X_ex)} nettoyé
        data_val_clean   : dict {src: (X_sh, X_ex)} nettoyé
        stats            : dict statistiques par source
        keep_indices     : dict {src: np.array indices gardés dans df_normal_raw}
    """
    stats        = {}
    keep_indices = {}   
    data_train_clean = {}
    data_val_clean   = {}

    print(f"\n Nettoyage (exclusion top CLEAN_PCT_BY_SOURCE% MSE par source) :")
    print(f"  {'Source':8s} | {'Avant':8s} | {'Exclu':6s} | {'Après':8s}")
    print("  " + "-" * 40)

    for src in SOURCES:
        if src not in data_train:
            continue

        X_sh_tr, X_ex_tr = data_train[src]

        # Calcul MSE sur le training set complet
        mse_tr = model.reconstruction_error(
            torch.FloatTensor(X_sh_tr).to(DEVICE),
            torch.FloatTensor(X_ex_tr).to(DEVICE),
            src,
        )

        # Seuil de nettoyage : exclure les top CLEAN_PCT%
        pct_clean       = CLEAN_PCT_BY_SOURCE.get(src, CLEAN_PCT)
        threshold_clean = np.percentile(mse_tr, 100 - pct_clean)
        keep            = mse_tr <= threshold_clean
        excluded        = (~keep).sum()

        # Indices gardés dans df_normal_raw (avant split train/val)
        # On reconstruit les indices globaux depuis les indices train
        # keep_indices[src] sera utilisé dans calibrate_thresholds
        keep_indices[src] = np.where(keep)[0]   # ← indices locaux au train

        # Training set nettoyé
        data_train_clean[src] = (X_sh_tr[keep], X_ex_tr[keep])

        # Même seuil appliqué sur la validation
        if src in data_val:
            X_sh_va, X_ex_va = data_val[src]
            if len(X_sh_va) > 0:
                mse_va  = model.reconstruction_error(
                    torch.FloatTensor(X_sh_va).to(DEVICE),
                    torch.FloatTensor(X_ex_va).to(DEVICE),
                    src,
                )
                keep_va             = mse_va <= threshold_clean
                data_val_clean[src] = (X_sh_va[keep_va], X_ex_va[keep_va])
            else:
                data_val_clean[src] = data_val[src]
        else:
            data_val_clean[src] = (np.array([]), np.array([]))

        stats[src] = {
            "before":   int(len(X_sh_tr)),
            "excluded": int(excluded),
            "after":    int(keep.sum()),
            "threshold_clean": round(float(threshold_clean), 6),
        }
        print(f"  {src:8s} | {len(X_sh_tr):8d} | {excluded:6d} | {keep.sum():8d}")

    return data_train_clean, data_val_clean, stats, keep_indices  # ← ajout keep_indices

# =============================================================================
# RISQUE 3 — SEUILS ADAPTATIFS PAR TRANCHE HORAIRE
# =============================================================================

HOUR_BANDS = {
    "business": lambda h, d: 9 <= h <= 18 and 1 <= d <= 5,
    "night":    lambda h, d: h >= 22 or h <= 5,
    "other":    lambda h, d: True,
}


def get_hour_band(hour: int, day_of_week: int) -> str:
    """Retourne la tranche horaire d'un log (business > night > other)."""
    for band, cond in HOUR_BANDS.items():
        if cond(int(hour), int(day_of_week)):
            return band
    return "other"

def get_tranches(X_train, hours=None, dows=None):
    """
    Divise X_train en 3 tranches horaires.
    Retourne une liste de (nom_tranche, masque_booleen).
    """
    if hours is None:
        hours = X_train[:, 0].astype(int)
    if dows is None:
        dows  = X_train[:, 1].astype(int)
    mask_business = np.array([get_hour_band(h, d) == "business" for h, d in zip(hours, dows)])
    mask_night    = np.array([get_hour_band(h, d) == "night"    for h, d in zip(hours, dows)])
    mask_other    = ~mask_business & ~mask_night
    return [("business", mask_business), ("night", mask_night), ("other", mask_other)]
# Remplace la logique de fallback dans calibrate_thresholds

def compute_source_global_p99(model, X_train, src, device, floor):
    """Calcule le P99 sur l'ensemble du training set de la source."""
    mse = compute_mse(model, X_train, src, device)
    p99 = float(np.percentile(mse, 99))
    return max(p99, floor)

def compute_mse(model, X_sh, X_ex, src, device):
    """Calcule la MSE de reconstruction sur un set (X_sh, X_ex)."""
    return model.reconstruction_error(
        torch.FloatTensor(X_sh).to(device),
        torch.FloatTensor(X_ex).to(device),
        src,
    )
def calibrate_thresholds(model, train_splits, device, df_normal_raw=None):
    thresholds = {}
    print("\n  Calibration seuils adaptatifs (P99) :")
    print(f"  {'Source':<8} | {'Tranche':<10} | {'N':<6} | {'P99':<10} | {'Seuil final':<12}")
    print(f"  {'-'*55}")

    for src, (X_sh, X_ex) in train_splits.items():
        floor = FLOOR_THRESHOLDS.get(src, 0.0)
        src_thresholds = {}

        # Extraire heures et jours depuis df_normal_raw (valeurs brutes, pas normalisées)
        if df_normal_raw is not None and src in df_normal_raw:
            df_src = df_normal_raw[src]
            # df_normal_raw[src] contient TOUS les normaux — prendre les train uniquement
            # len(X_sh) = taille du train set après nettoyage
            df_train_part = df_src.iloc[:len(X_sh)]
            hours = pd.to_numeric(
                df_train_part.get("hour_of_day", 12), errors="coerce"
            ).fillna(12).astype(int).values
            dows  = pd.to_numeric(
                df_train_part.get("day_of_week", 3), errors="coerce"
            ).fillna(3).astype(int).values
        else:
            # Fallback : toutes les tranches auront les mêmes données
            hours = np.full(len(X_sh), 12)
            dows  = np.full(len(X_sh), 2)

        for tranche, mask in get_tranches(X_sh, hours, dows):
            X_sh_t = X_sh[mask]
            X_ex_t = X_ex[mask]
            n      = len(X_sh_t)

            if n < 50:
                mse   = compute_mse(model, X_sh, X_ex, src, device)
                p99   = float(np.percentile(mse, 99))
                final = max(p99, floor)
                print(f"  {src:<8} | {tranche:<10} | {n:<6} | "
                      f"{p99:.6f} (fallback global) | {final:.6f}")
            else:
                mse   = compute_mse(model, X_sh_t, X_ex_t, src, device)
                p99   = float(np.percentile(mse, 99))
                final = max(p99, floor)
                print(f"  {src:<8} | {tranche:<10} | {n:<6} | "
                      f"{p99:.6f} | {final:.6f}")

            src_thresholds[tranche] = final

        thresholds[src] = src_thresholds

    return thresholds
def get_threshold(thresholds: dict, src: str,
                  hour: int = 12, day_of_week: int = 2) -> float:
    """Retourne le seuil adaptatif pour un event selon source + heure."""
    if src not in thresholds:
        return 0.5
    band = get_hour_band(hour, day_of_week)
    d    = thresholds[src]
    return d.get(band, d.get("_global", 0.5))


# =============================================================================
# SECTION I — ÉVALUATION
# =============================================================================

def compute_predictions(model, df_test, scalers, thresholds):
    """
    Prédictions avec seuils adaptatifs (risque 3 corrigé).
    Le seuil varie selon l'heure de chaque log.
    """
    all_mse, all_pred, all_true, all_src = [], [], [], []

    for src in SOURCES:
        if src not in scalers:
            continue
        df_src = df_test[df_test["log_source"] == src].reset_index(drop=True)
        if len(df_src) == 0:
            continue

        sc_sh, sc_ex = scalers[src]
        X_sh, X_ex, _, _ = preprocess_source(df_src, src, sc_sh, sc_ex,
                                              fit=False)
        mse = model.reconstruction_error(
            torch.FloatTensor(X_sh).to(DEVICE),
            torch.FloatTensor(X_ex).to(DEVICE),
            src,
        )

        # RISQUE 3 — seuil adaptatif par log selon son heure
        hours = pd.to_numeric(
            df_src.get("hour_of_day", 12), errors="coerce"
        ).fillna(12).astype(int).values
        dows  = pd.to_numeric(
            df_src.get("day_of_week", 3), errors="coerce"
        ).fillna(3).astype(int).values

        pred = np.array([
            1 if mse[i] > get_threshold(thresholds, src, hours[i], dows[i])
            else 0
            for i in range(len(mse))
        ])

        true = df_src["ground_truth"].values.astype(int) \
               if "ground_truth" in df_src.columns \
               else np.zeros(len(df_src), dtype=int)

        all_mse.extend(mse.tolist())
        all_pred.extend(pred.tolist())
        all_true.extend(true.tolist())
        all_src.extend([src] * len(df_src))

        thr_ref = get_threshold(thresholds, src, 12, 2)
        print(f"  {src:8s}: {pred.sum():4d} anomalies | "
              f"{true.sum():4d} vraies | seuil ref={thr_ref:.6f}")

    return (np.array(all_true), np.array(all_pred),
            np.array(all_mse),  np.array(all_src))


def compute_global_metrics(y_true, y_pred, y_score):
    prec    = float(precision_score(y_true, y_pred, zero_division=0))
    rec     = float(recall_score(y_true, y_pred, zero_division=0))
    f1      = float(f1_score(y_true, y_pred, zero_division=0))
    auc_roc = float(roc_auc_score(y_true, y_score))
    auc_pr  = float(average_precision_score(y_true, y_score))
    cm      = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    mse_n   = float(y_score[y_true==0].mean()) if (y_true==0).sum() > 0 else 0.0
    mse_a   = float(y_score[y_true==1].mean()) if (y_true==1).sum() > 0 else 0.0
    return {
        "precision":  round(prec,    4),
        "recall":     round(rec,     4),
        "f1_score":   round(f1,      4),
        "auc_roc":    round(auc_roc, 4),
        "auc_pr":     round(auc_pr,  4),
        "mse_normal": round(mse_n,   6),
        "mse_attack": round(mse_a,   6),
        "mse_ratio":  round(mse_a / max(mse_n, 1e-9), 2),
        "cm": {"tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)},
    }


def evaluate_by_attack_type(y_pred, df_test):
    if "attack_type" not in df_test.columns:
        return {}
    result = {}
    print("\n  Rappel par type d'attaque :")
    print("  " + "─" * 56)
    for atype in sorted(df_test["attack_type"].unique()):
        if atype == "normal":
            continue
        mask     = (df_test["attack_type"].values == atype)
        total    = mask.sum()
        if total == 0:
            continue
        detected = y_pred[mask].sum()
        rate     = detected / total
        result[atype] = {
            "recall": round(float(rate), 4),
            "detected": int(detected), "total": int(total),
        }
        icon = "✓" if rate >= 0.8 else ("~" if rate >= 0.5 else "✗ ANGLE MORT")
        print(f"  {icon:14s} {str(atype):26s}: "
              f"{detected:3d}/{total:3d} ({rate*100:.0f}%)")
    print("  " + "─" * 56)
    return result


def measure_inference_time(model, scalers, df_test, n_repeats=5):
    results  = {"by_source": {}, "total_ms": 0.0, "per_event_us": 0.0}
    total_ms, total_ev = 0.0, 0
    for src in SOURCES:
        if src not in scalers:
            continue
        df_src = df_test[df_test["log_source"] == src]
        if len(df_src) == 0:
            continue
        sc_sh, sc_ex = scalers[src]
        X_sh, X_ex, _, _ = preprocess_source(df_src, src, sc_sh, sc_ex, fit=False)
        t_sh = torch.FloatTensor(X_sh).to(DEVICE)
        t_ex = torch.FloatTensor(X_ex).to(DEVICE)
        _ = model.reconstruction_error(t_sh[:10], t_ex[:10], src)
        times = []
        for _ in range(n_repeats):
            t0 = time.perf_counter()
            _  = model.reconstruction_error(t_sh, t_ex, src)
            times.append((time.perf_counter() - t0) * 1000)
        mean_ms = float(np.mean(times))
        per_us  = mean_ms / len(df_src) * 1000
        results["by_source"][src] = {
            "n_events": int(len(df_src)),
            "mean_ms":  round(mean_ms, 3),
            "std_ms":   round(float(np.std(times)), 3),
            "per_us":   round(per_us, 2),
        }
        print(f"  {src:8s}: {mean_ms:.3f}ms (±{np.std(times):.3f}) | "
              f"{per_us:.2f}µs/event")
        total_ms += mean_ms
        total_ev += len(df_src)
    results["total_ms"]     = round(total_ms, 3)
    results["per_event_us"] = round(total_ms / max(total_ev, 1) * 1000, 2)
    print(f"  TOTAL : {total_ms:.3f}ms | {results['per_event_us']:.2f}µs/event")
    return results


def measure_robustness(y_score, y_true, thresholds, src_arr,
                       df_test,                        # ← nouveau paramètre
                       n_bootstrap=N_BOOTSTRAP):
    rng = np.random.default_rng(123)
    n   = len(y_true)
    acc = {"f1": [], "precision": [], "recall": [], "auc_roc": []}

    # Extraire heure et jour UNE SEULE FOIS avant la boucle
    hours_all = pd.to_numeric(
        df_test.get("hour_of_day", 12), errors="coerce"
    ).fillna(12).astype(int).values
    dows_all  = pd.to_numeric(
        df_test.get("day_of_week", 3), errors="coerce"
    ).fillna(3).astype(int).values

    for _ in range(n_bootstrap):
        idx = rng.choice(n, size=int(n * BOOTSTRAP_PCT), replace=False)
        y_t = y_true[idx]
        m   = y_score[idx]
        src = src_arr[idx]

        if y_t.sum() == 0 or y_t.sum() == len(y_t):
            continue

        # Seuils adaptatifs par log selon son heure
        y_p = np.array([
            1 if mi > get_threshold(thresholds, si,
                                    hours_all[idx[i]],
                                    dows_all[idx[i]])
            else 0
            for i, (mi, si) in enumerate(zip(m, src))
        ])

        acc["f1"].append(f1_score(y_t, y_p, zero_division=0))
        acc["precision"].append(precision_score(y_t, y_p, zero_division=0))
        acc["recall"].append(recall_score(y_t, y_p, zero_division=0))
        try:
            acc["auc_roc"].append(roc_auc_score(y_t, m))
        except Exception:
            pass

    robustness = {}
    for k, vals in acc.items():
        v = np.array(vals)
        robustness[k] = {
            "mean":   round(float(np.mean(v)), 4),
            "std":    round(float(np.std(v)),  4),
            "cv_pct": round(float(np.std(v) / max(np.mean(v), 1e-9) * 100), 2),
        }
        print(f"  {k:12s}: {robustness[k]['mean']:.4f} ± "
              f"{robustness[k]['std']:.4f} "
              f"(CV={robustness[k]['cv_pct']:.1f}%)")
    return robustness

# =============================================================================
# SECTION J — GRAPHIQUES
# =============================================================================

def plot_all(train_hist, val_hist, y_true, y_pred, y_score,
             thresholds, src_arr, gm, timing, robustness, attack_result):
    os.makedirs(PLOTS_DIR, exist_ok=True)

    # 1. Courbes train/val
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(train_hist, lw=1.5, color="steelblue", label="Train")
    ax.plot(val_hist,   lw=1.5, color="tomato",    label="Val")
    best = int(np.argmin(val_hist))
    ax.axvline(best, color="gray", lw=1, ls="--",
               label=f"Best ep.{best+1} ({min(val_hist):.6f})")
    ax.set_xlabel("Epoch"); ax.set_ylabel("Huber Loss")
    ax.set_title("Entraînement / Validation")
    ax.legend(); ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/loss_curves.png", dpi=150); plt.close()

    # 2. Matrice de confusion
    cm_arr = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(cm_arr, cmap="Blues")
    plt.colorbar(im, ax=ax)
    ax.set_xticks([0,1]); ax.set_yticks([0,1])
    ax.set_xticklabels(["Normal","Attaque"])
    ax.set_yticklabels(["Normal","Attaque"])
    ax.set_xlabel("Prédit"); ax.set_ylabel("Réel")
    ax.set_title("Matrice de confusion")
    th_cm = cm_arr.max() / 2
    for i in range(2):
        for j in range(2):
            ax.text(j, i,
                    f"{cm_arr[i,j]}\n({cm_arr[i,j]/cm_arr.sum()*100:.1f}%)",
                    ha="center", va="center", fontsize=13, fontweight="bold",
                    color="white" if cm_arr[i,j] > th_cm else "black")
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/confusion_matrix.png", dpi=150); plt.close()

    # 3. ROC + PR
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fpr, tpr, _ = roc_curve(y_true, y_score)
    axes[0].plot(fpr, tpr, lw=2, color="steelblue",
                 label=f"AUC-ROC={gm['auc_roc']:.4f}")
    axes[0].plot([0,1],[0,1],"k--",lw=1)
    axes[0].fill_between(fpr, tpr, alpha=0.1, color="steelblue")
    axes[0].set_xlabel("FPR"); axes[0].set_ylabel("TPR")
    axes[0].set_title("Courbe ROC"); axes[0].legend()
    axes[0].grid(True, alpha=0.3)
    prec_c, rec_c, _ = precision_recall_curve(y_true, y_score)
    axes[1].plot(rec_c, prec_c, lw=2, color="tomato",
                 label=f"AUC-PR={gm['auc_pr']:.4f}")
    axes[1].fill_between(rec_c, prec_c, alpha=0.1, color="tomato")
    axes[1].set_xlabel("Rappel"); axes[1].set_ylabel("Précision")
    axes[1].set_title("Précision-Rappel"); axes[1].legend()
    axes[1].grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/roc_pr_curves.png", dpi=150); plt.close()

    # 4. Distribution MSE
    n_cols = len(SOURCES) + 1
    fig, axes = plt.subplots(1, n_cols, figsize=(5*n_cols, 4))
    fig.suptitle("Distribution MSE — Normal vs Attaque")
    axes[0].hist(y_score[y_true==0], bins=60, alpha=0.6,
                 color="steelblue", density=True, label="Normal")
    axes[0].hist(y_score[y_true==1], bins=60, alpha=0.6,
                 color="tomato", density=True, label="Attaque")
    axes[0].set_title("Toutes sources")
    axes[0].legend(); axes[0].grid(True, alpha=0.3)
    for i, src in enumerate(SOURCES):
        ax   = axes[i+1]
        mask = (src_arr == src)
        if mask.sum() == 0:
            continue
        thr = get_threshold(thresholds, src)
        ax.hist(y_score[mask & (y_true==0)], bins=40, alpha=0.6,
                color="steelblue", density=True, label="Normal")
        if (mask & (y_true==1)).sum() > 0:
            ax.hist(y_score[mask & (y_true==1)], bins=40, alpha=0.6,
                    color="tomato", density=True, label="Attaque")
        ax.axvline(thr, color="black", lw=2, ls="--",
                   label=f"seuil={thr:.5f}")
        ax.set_title(src); ax.legend(fontsize=8); ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/mse_distribution.png", dpi=150); plt.close()

    # 5. Timing
    srcs = list(timing["by_source"].keys())
    cols = ["steelblue","tomato","seagreen"][:len(srcs)]
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))
    axes[0].bar(srcs, [timing["by_source"][s]["mean_ms"] for s in srcs],
                color=cols, alpha=0.8)
    axes[0].set_ylabel("ms"); axes[0].set_title("Temps batch")
    axes[0].grid(True, alpha=0.3, axis="y")
    axes[1].bar(srcs, [timing["by_source"][s]["per_us"] for s in srcs],
                color=cols, alpha=0.8)
    axes[1].set_ylabel("µs"); axes[1].set_title("Temps / event")
    axes[1].grid(True, alpha=0.3, axis="y")
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/inference_timing.png", dpi=150); plt.close()

    # 6. Robustesse bootstrap
    rkeys = ["f1","precision","recall","auc_roc"]
    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(len(rkeys))
    ax.bar(x, [robustness[k]["mean"] for k in rkeys],
           yerr=[robustness[k]["std"] for k in rkeys],
           capsize=8,
           color=["#2196F3","#4CAF50","#FF9800","#9C27B0"], alpha=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels(["F1","Précision","Rappel","AUC-ROC"])
    ax.set_ylim(0, 1.15)
    ax.set_title(f"Robustesse — {N_BOOTSTRAP} bootstrap")
    ax.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/robustness.png", dpi=150); plt.close()

    # 7. Rappel par type d'attaque
    if attack_result:
        types   = list(attack_result.keys())
        recalls = [attack_result[t]["recall"] for t in types]
        sidx    = np.argsort(recalls)
        bar_colors = [
            "tomato"   if recalls[i] < 0.5 else
            "orange"   if recalls[i] < 0.8 else
            "seagreen" for i in sidx
        ]
        fig, ax = plt.subplots(figsize=(11, max(5, len(types)*0.7)))
        bars = ax.barh([types[i] for i in sidx],
                       [recalls[i] for i in sidx],
                       color=bar_colors, alpha=0.85)
        for bar, idx in zip(bars, sidx):
            t = types[idx]
            ax.text(bar.get_width() + 0.01,
                    bar.get_y() + bar.get_height()/2,
                    f"{attack_result[t]['detected']}/{attack_result[t]['total']}",
                    va="center", fontsize=9)
        ax.axvline(0.5, color="gray",      lw=1.5, ls="--", label="50%")
        ax.axvline(0.8, color="steelblue", lw=1.5, ls="--", label="80%")
        ax.set_xlabel("Rappel (taux de détection)")
        ax.set_title("Rappel par type d'attaque\n"
                     "Rouge = angle mort | Orange = à améliorer | Vert = bon")
        ax.set_xlim(0, 1.2); ax.legend()
        ax.grid(True, alpha=0.3, axis="x")
        plt.tight_layout()
        plt.savefig(f"{PLOTS_DIR}/recall_by_attack.png", dpi=150); plt.close()

    print(f"  Graphiques → {PLOTS_DIR}/")


# =============================================================================
# SECTION K — ÉCRITURE ES
# =============================================================================

def safe_int(val, default=0): # pour gérer les valeur NaN, None et les floats dans composite_score
    """Convertit en int en gérant NaN, None et les floats."""
    try:
        if val is None:
            return default
        f = float(val)
        return default if math.isnan(f) or math.isinf(f) else int(f)
    except (ValueError, TypeError):
        return default

def safe_str(val, default="unknown"):
    """Convertit en str en gérant NaN et None."""
    if val is None:
        return default
    try:
        if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
            return default
    except Exception:
        pass
    return str(val)


def write_to_elasticsearch(df_result, thresholds, batch_size=500):
    """
    Écrit les anomalies dans ml-autoencoder-scores via l'API bulk.
    Retourne df_result enrichi avec la colonne "_es_write_id".
 
    CORRECTIONS :
      1. sanitize_for_json() élimine NaN/Inf avant json.dumps
         → plus de "Non-standard token 'NaN'" (14029 erreurs → 0)
      2. Parse la réponse bulk pour récupérer les IDs générés par ES
         → _es_write_id utilisé par run_llm_explanation_pipeline
    """
    ctx, headers = make_es_client()
    anomalies    = df_result[df_result["ae_is_anomaly"] == 1].copy()
 
    if len(anomalies) == 0:
        print("  Aucune anomalie à écrire")
        df_result["_es_write_id"] = None
        return df_result
 
    print(f"  Écriture {len(anomalies)} anomalies → {ES_INDEX_WRITE}")
 
    # ── Construction des documents ────────────────────────────────
    docs_ordered = []   # list of (original_index, doc_dict)
 
    for orig_idx, row in anomalies.iterrows():
        src   = str(row.get("log_source", "unknown"))
        score = float(row.get("ae_mse_error", 0))
        thr   = get_threshold(thresholds, src)
        p99   = thr * 3 + 1e-9
        norm  = float(np.clip(np.log1p(score) / np.log1p(p99), 0, 1))
 
        # Features ML : uniquement celles de la bonne source + shared
        ml_keys = list(dict.fromkeys(
            SHARED_FEATURES + EXPERT_FEATURES.get(src, []) + ["log_source"]
        ))
        ml_dict = {}
        for k in ml_keys:
            v = row.get(k)
            # Convertit numpy scalars + NaN ici aussi (double sécurité)
            if isinstance(v, (np.integer,)):
                v = int(v)
            elif isinstance(v, (np.floating,)):
                v = float(v)
            if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                v = None
            ml_dict[k] = v
 
        doc = {
            "@timestamp":       datetime.now(timezone.utc).isoformat(),
            "source_id":        str(row.get("_id", "unknown")),
            "log_source":       src,
            "ae_mse_error":     round(score, 6),
            "ae_anomaly_score": round(norm,  4),
            "ae_is_anomaly":    1,
            "ae_threshold":     round(thr,   6),
            "composite_score":  safe_int(row.get("composite_score"), 0),
            "priority_label":   safe_str(row.get("priority_label"), "unknown"),
            "ml":               ml_dict,
        }
 
        # Nettoyage global récursif — capture tout ce qui aurait été manqué
        doc = sanitize_for_json(doc)
        docs_ordered.append((orig_idx, doc))
 
    # ── Envoi par batches + collecte des IDs générés ──────────────
    id_map = {}   # original_index → es_generated_id
 
    def send_batch(batch):
        bulk_body = ""
        for _, doc in batch:
            bulk_body += json.dumps({"index": {"_index": ES_INDEX_WRITE}}) + "\n"
            bulk_body += json.dumps(doc) + "\n"   # NaN impossible ici
 
        req = urllib.request.Request(
            f"{ES_HOST}/_bulk",
            data    = bulk_body.encode(),
            headers = headers,
            method  = "POST",
        )
        resp     = urllib.request.urlopen(req, context=ctx)
        resp_obj = json.loads(resp.read())
 
        result = {}
        for pos, item in enumerate(resp_obj.get("items", [])):
            action = item.get("index", {})
            if action.get("result") in ("created", "updated"):
                result[pos] = action["_id"]
            elif action.get("error"):
                # Log court — juste le type d'erreur, pas le JSON complet
                err_type = action["error"].get("type", "unknown")
                err_reason = action["error"].get("reason", "")[:120]
                print(f"  [ES] Erreur doc {pos}: {err_type} — {err_reason}")
        return result
 
    for start in range(0, len(docs_ordered), batch_size):
        batch     = docs_ordered[start : start + batch_size]
        batch_ids = send_batch(batch)
 
        for pos, (orig_idx, _) in enumerate(batch):
            es_id = batch_ids.get(pos)
            if es_id:
                id_map[orig_idx] = es_id
 
        written_so_far = start + len(batch)
        if written_so_far % (batch_size * 4) == 0 or written_so_far == len(docs_ordered):
            print(f"    {written_so_far}/{len(docs_ordered)} docs traités...")
 
    # ── Injecte les IDs dans df_result ────────────────────────────
    df_result = df_result.copy()
    df_result["_es_write_id"] = None
 
    for orig_idx, es_id in id_map.items():
        df_result.at[orig_idx, "_es_write_id"] = es_id
 
    n_written = len(id_map)
    n_failed  = len(anomalies) - n_written
    print(f"  {n_written} anomalies écrites | {n_failed} erreurs ES")
    return df_result
 

# =============================================================================
# SECTION L — MAIN
# =============================================================================

if __name__ == "__main__":
    print("=" * 65)
    print("  MoE-AE IDS — PIPELINE v2 (4 risques corrigés)")
    print(f"  Device  : {DEVICE}")
    print(f"  Shared  : {SHARED_DIM} features")
    for s, d in EXPERT_DIMS.items():
        print(f"  {s:8s}: {d} features expert")
    
    print("=" * 65)

    os.makedirs(PLOTS_DIR, exist_ok=True)

    # ── [1/9] Chargement logs réels + synthétiques ────────────────
    print("\n[1/9] Chargement des données d'entraînement...")
    df_real  = load_training_data()
    df_synth = load_synthetic_normal()
    df_raw   = merge_training_data(df_real, df_synth)
    if len(df_raw) == 0:
        print("ERREUR : aucune donnée d'entraînement")
        exit(1)
    if "log_source" in df_raw.columns:
        for src, cnt in df_raw["log_source"].value_counts().items():
            print(f"  {str(src):10s}: {cnt:7d}")

    # ── [2/9] Chargement jeu de test ──────────────────────────────
    print(f"\n[2/9] Chargement du jeu de test ({ES_INDEX_TEST})...")
    df_test = load_test_data()
    if len(df_test) == 0:
        print(f"ERREUR : {ES_INDEX_TEST} vide")
        exit(1)

    # ── [3/9] Split Train / Val ───────────────────────────────────
    print("\n[3/9] Séparation par source + split Train/Val...")
    dfs_by_source   = {}
    data_train      = {}
    data_val        = {}
    data_all_normal = {}
    df_normal_raw   = {}   # pour calibration seuils adaptatifs (risque 3)
    scalers         = {}

    for src in SOURCES:
        if "log_source" not in df_raw.columns:
            break
        df_src = df_raw[df_raw["log_source"] == src].reset_index(drop=True)
        if len(df_src) == 0:
            continue

        dfs_by_source[src] = df_src
        normal_mask        = build_normal_mask(df_src)
        df_normal          = df_src[normal_mask].reset_index(drop=True)
        pct                = len(df_normal) / max(len(df_src), 1) * 100
        print(f"\n  {src}: {len(df_src):6d} total | "
              f"{len(df_normal):5d} normaux ({pct:.1f}%)")

        if len(df_normal) < 50:
            print(f"  ⚠ {src} : insuffisant (< 50 normaux)")
            continue

        idx_all            = np.arange(len(df_normal))
        idx_train, idx_val = train_test_split(
            idx_all, test_size=VAL_RATIO, random_state=42
        )
        df_tr = df_normal.iloc[idx_train].reset_index(drop=True)
        df_va = df_normal.iloc[idx_val].reset_index(drop=True)
        print(f"  {src} split : {len(idx_train)} train | {len(idx_val)} val")

        X_sh_tr, X_ex_tr, sc_sh, sc_ex = preprocess_source(
            df_tr, src, fit=True
        )
        X_sh_va, X_ex_va, _, _ = preprocess_source(
            df_va, src, sc_sh, sc_ex, fit=False
        )
        X_sh_all, X_ex_all, _, _ = preprocess_source(
            df_normal, src, sc_sh, sc_ex, fit=False
        )

        scalers[src]          = (sc_sh, sc_ex)
        data_train[src]       = (X_sh_tr, X_ex_tr)
        data_val[src]         = (X_sh_va, X_ex_va)
        data_all_normal[src]  = (X_sh_all, X_ex_all)
        df_normal_raw[src]    = df_normal   # conservé pour risque 3

    if not data_train:
        print("ERREUR : aucune source avec assez de normaux")
        exit(1)

    # ── [4/9] Création du modèle ───────────────────────────────────
    print("\n[4/9] Création du modèle MoEAutoencoderV2...")
    model = MoEAutoencoder(SHARED_DIM, EXPERT_DIMS, LATENT_DIM).to(DEVICE)
    print(f"  Paramètres : {sum(p.numel() for p in model.parameters()):,}")
    print(f"  Alphas initiaux : { {src: round(model.get_alpha(src).item(), 3) for src in model._alpha_raw} }")

    # ── [5/9] Entraînement — PASSE 1 ─────────────────────────────
    print("\n[5/9] Entraînement — Passe 1 (set complet)...")
    model, train_hist_1, val_hist_1, dur_1 = train(
        model, data_train, data_val
    )

    # ── RISQUE 4 — Nettoyage itératif ─────────────────────────────
    print("\n  [RISQUE 4] Nettoyage itératif du training set...")
    data_train_clean, data_val_clean, cleaning_stats,keep_indices = clean_training_set(
        model, data_train, data_val
    )

    # ── [5/9] Entraînement — PASSE 2 (set nettoyé) ───────────────
    print("\n  [RISQUE 4] Entraînement — Passe 2 (set nettoyé)...")
    model2 = MoEAutoencoder(SHARED_DIM, EXPERT_DIMS, LATENT_DIM).to(DEVICE)
    model2, train_hist, val_hist, duration = train(
        model2, data_train_clean, data_val_clean
    )
    model = model2   # le modèle final est celui de la passe 2

    print("\n  Alphas appris après entraînement :")
    for src in model._alpha_raw:
        alpha_val = model.get_alpha(src).item()
        print(f"    {src:<8}: {alpha_val:.3f} shared / {1-alpha_val:.3f} expert")   

    torch.save(model.state_dict(), MODEL_PATH)
    joblib.dump(scalers, SCALERS_PATH)
    print(f"  Modèle → {MODEL_PATH} | Scalers → {SCALERS_PATH}")

    # ── [6/9] Calibration seuils adaptatifs ──────────────────────
    print("\n[6/9] Calibration seuils adaptatifs (risque 3)...")
    # Fusionner train_clean + val_clean pour la calibration
    data_all_clean = {}
    for src in SOURCES:
        if src in data_train_clean and src in data_val_clean:
            X_sh_tr, X_ex_tr = data_train_clean[src]
            X_sh_va, X_ex_va = data_val_clean[src]
            if len(X_sh_va) > 0:
                data_all_clean[src] = (
                    np.vstack([X_sh_tr, X_sh_va]),
                    np.vstack([X_ex_tr, X_ex_va]),
                )
            else:
                data_all_clean[src] = data_train_clean[src]
        elif src in data_train_clean:
            data_all_clean[src] = data_train_clean[src]

    thresholds = calibrate_thresholds(
        model, data_train_clean, DEVICE, df_normal_raw
    )
    joblib.dump(thresholds, THRESH_PATH)
    print(f"  Seuils → {THRESH_PATH}")

    # ── [7/9] Évaluation complète ────────────────────────────────
    print("\n[7/9] Évaluation sur le jeu de test...")
    y_true, y_pred, y_score, src_arr = compute_predictions(
        model, df_test, scalers, thresholds
    )
    if y_true.sum() == 0:
        print("ERREUR : aucun positif dans le test")
        exit(1)

    print(f"\n  Ground truth : {y_true.sum()} attaques / {len(y_true)} events")
    gm = compute_global_metrics(y_true, y_pred, y_score)

    print(f"""
  ┌──────────────────────────────────────────────────────┐
  │  1. PRÉCISION    : {gm['precision']:.4f}                         │
  │  2. RAPPEL       : {gm['recall']:.4f}                         │
  │  3. F1-SCORE     : {gm['f1_score']:.4f}                         │
  │  6. MATRICE CONF.: TP={gm['cm']['tp']:4d}  FP={gm['cm']['fp']:4d}           │
  │                    FN={gm['cm']['fn']:4d}  TN={gm['cm']['tn']:4d}           │
  │  7. MSE normal   : {gm['mse_normal']:.6f}                    │
  │     MSE attaque  : {gm['mse_attack']:.6f}                    │
  │     Ratio MSE    : x{gm['mse_ratio']:.1f}                           │
  ├──────────────────────────────────────────────────────┤
  │  AUC-ROC         : {gm['auc_roc']:.4f}                         │
  │  AUC-PR          : {gm['auc_pr']:.4f}                         │
  └──────────────────────────────────────────────────────┘""")

    attack_result = evaluate_by_attack_type(y_pred, df_test)

    print("\n  Métriques par source :")
    metrics_by_source = {}
    for src in SOURCES:
        mask = (src_arr == src)
        if mask.sum() == 0 or y_true[mask].sum() == 0:
            continue
        metrics_by_source[src] = {
            "precision": round(float(precision_score(
                y_true[mask], y_pred[mask], zero_division=0)), 4),
            "recall":    round(float(recall_score(
                y_true[mask], y_pred[mask], zero_division=0)), 4),
            "f1":        round(float(f1_score(
                y_true[mask], y_pred[mask], zero_division=0)), 4),
            "auc_roc":   round(float(roc_auc_score(
                y_true[mask], y_score[mask])), 4),
        }
        print(f"  {src:8s}: P={metrics_by_source[src]['precision']:.4f} | "
              f"R={metrics_by_source[src]['recall']:.4f} | "
              f"F1={metrics_by_source[src]['f1']:.4f}")

    # ── [8/9] Timing + Robustesse ─────────────────────────────────
    print("\n[8/9] Timing d'inférence + robustesse bootstrap...")
    print("\n  Temps d'inférence :")
    timing = measure_inference_time(model, scalers, df_test)
    print(f"\n  Robustesse ({N_BOOTSTRAP} bootstrap) :")
    robustness = measure_robustness(y_score, y_true, thresholds, src_arr, df_test)

    print("\n  Génération des graphiques...")
    plot_all(train_hist, val_hist, y_true, y_pred, y_score,
             thresholds, src_arr, gm, timing, robustness, attack_result)

    # ── [9/9] Inférence production + écriture ES ──────────────────
# ── [9/9] Inférence production + écriture ES ──────────────────
    print("\n[9/9] Inférence production + écriture ES...")
    results = []
    for src in SOURCES:
        if src not in dfs_by_source or src not in scalers:
            continue
        df_src   = dfs_by_source[src]

        sc_sh, sc_ex = scalers[src]
        X_sh, X_ex, _, _ = preprocess_source(
            df_src, src, sc_sh, sc_ex, fit=False
        )
        mse = model.reconstruction_error(
            torch.FloatTensor(X_sh).to(DEVICE),
            torch.FloatTensor(X_ex).to(DEVICE),
            src,
        )

        # Seuil adaptatif par log
        hours = pd.to_numeric(
            df_src.get("hour_of_day", 12), errors="coerce"
        ).fillna(12).astype(int).values
        dows  = pd.to_numeric(
            df_src.get("day_of_week", 3), errors="coerce"
        ).fillna(3).astype(int).values

        thr_arr = np.array([
            get_threshold(thresholds, src, hours[i], dows[i])
            for i in range(len(mse))
        ])

        p99    = np.percentile(mse, 99) + 1e-9
        df_src = df_src.copy()
        df_src["ae_mse_error"]     = np.round(mse, 6)
        df_src["ae_anomaly_score"] = np.round(
            np.clip(np.log1p(mse) / np.log1p(p99), 0, 1), 4
        )
        if src == "auditd":
            composite = pd.to_numeric(
                df_src.get("composite_score", 0), errors="coerce"
            ).fillna(0).values
            df_src["ae_is_anomaly"] = (
                (mse > thr_arr) & (composite >= 1)
            ).astype(int)
        else:
            df_src["ae_is_anomaly"] = (mse > thr_arr).astype(int)

        df_src["ae_threshold"] = thr_arr

        n_anom = (mse > thr_arr).sum()
        print(f"  {src:8s}: {n_anom:4d}/{len(df_src):6d} anomalies")
        results.append(df_src)

    # ── Concaténation — df_result défini ICI avant tout appel ─────
    df_result = pd.concat(results, ignore_index=True)

    # ── Écriture ES — retourne df_result enrichi avec _es_write_id ─
    df_result = write_to_elasticsearch(df_result, thresholds)

    # ── Explication LLM haute priorité (un seul appel) ────────────
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))
        from fusion_router import FusionRouter
        router = FusionRouter()
        router.process_dataframe(df_result, thresholds)
    except Exception as e:
        print(f"\n  [FUSION] Skipped — {e}")
 

    print("\n" + "=" * 65)
    print("  PIPELINE TERMINÉ")
    print("=" * 65)
#     print(f"""
#   Corrections appliquées :
#     """✓ Risque 1 : Redis {'actif' if redis_store.available else 'absent (fallback)'}"""
#     ✓ Risque 2 : Alphas appris = {model.get_alphas()}
#     ✓ Risque 3 : Seuils adaptatifs par tranche horaire
#     ✓ Risque 4 : Nettoyage itératif ({CLEAN_PCT}% exclus par source)

#   Fichiers produits :
#     {MODEL_PATH}  {SCALERS_PATH}  {THRESH_PATH}
#     {REPORT_PATH}
#     {PLOTS_DIR}/loss_curves.png
#     {PLOTS_DIR}/confusion_matrix.png
#     {PLOTS_DIR}/roc_pr_curves.png
#     {PLOTS_DIR}/mse_distribution.png
#     {PLOTS_DIR}/inference_timing.png
#     {PLOTS_DIR}/robustness.png
#     {PLOTS_DIR}/recall_by_attack.png
# """)