"""
=============================================================================
controllers/stats_controller.py  (version pymongo / sync)
Logique métier du dashboard expert IA.
=============================================================================
"""
from models.metrics_model import MetricsRepository

repo = MetricsRepository()

HIGHER_IS_BETTER = {"precision", "recall", "f1_score", "auc_roc", "auc_pr"}
LOWER_IS_BETTER = {"best_val_loss", "per_event_us", "fp"}


def _trend(current, previous, metric: str) -> dict:
    if current is None:
        return {"value": None, "delta": None, "trend": "neutral"}
    if previous is None:
        return {"value": current, "delta": None, "trend": "new"}
    diff = round(current - previous, 6)
    if abs(diff) < 1e-6:
        trend = "neutral"
    else:
        improved = (diff > 0) if metric in HIGHER_IS_BETTER else (diff < 0)
        trend = "up" if improved else "down"
    return {"value": current, "delta": diff, "trend": trend}


def list_versions():
    versions = repo.list_versions()
    return {
        "versions": versions,
        "count": len(versions),
        "comparison_available": len(versions) >= 2,
    }


def get_overview(version: str | None = None):
    doc = repo.get_version(version) if version else repo.get_latest()
    if not doc:
        return None
    return {
        "version": doc.get("version"),
        "ingested_at": doc.get("ingested_at"),
        "hyperparameters": doc.get("hyperparameters", {}),
        "architecture": doc.get("architecture", {}),
        "model_params": {
            "total_params": doc.get("total_params"),
            "epochs_trained": doc.get("epochs_trained"),
            "best_val_loss": doc.get("best_val_loss"),
            "train_duration_s": doc.get("train_duration_s"),
            "device": doc.get("device"),
            "alphas_learned": doc.get("alphas_learned", {}),
        },
        "thresholds": doc.get("thresholds", {}),
        "cleaning_stats": doc.get("cleaning_stats", {}),
        "global_metrics": doc.get("global_metrics", {}),
        "metrics_by_source": doc.get("metrics_by_source", {}),
        "attack_result": doc.get("attack_result", {}),
        "inference_timing": doc.get("inference_timing", {}),
        "robustness": doc.get("robustness", {}),
    }


"""
=============================================================================
controllers/stats_controller_ai.py  —  _build_comparison COMPLET
Remplace ta fonction _build_comparison existante par celle-ci.
Ajoute : robustness[], inference_timing[], patience + device aux hyperparams.
Le reste (list_versions, get_overview, compare_versions, _trend) est inchangé.
=============================================================================
"""


def _build_comparison(ordered: list[dict]) -> dict:
    result = {
        "versions": [d["version"] for d in ordered],
        "comparison_available": len(ordered) >= 2,
        "global_metrics": [],
        "hyperparameters": [],
        "by_attack": {},
        "by_source": {},
        "model_info": [],
        "robustness": [],
        "inference_timing": [],
        "separation": [],       # ratio MSE normal/attaque (séparation AE)
        "thresholds": [],       # seuils de décision par source/contexte
        "cleaning": [],         # stats de nettoyage du jeu d'entraînement
    }

    prev_gm = None
    prev_val_loss = None
    for d in ordered:
        gm = d.get("global_metrics", {})
        row = {"version": d["version"]}
        for m in HIGHER_IS_BETTER:
            row[m] = _trend(gm.get(m), prev_gm.get(m) if prev_gm else None, m)
        row["best_val_loss"] = _trend(d.get("best_val_loss"), prev_val_loss, "best_val_loss")
        result["global_metrics"].append(row)
        prev_gm = gm
        prev_val_loss = d.get("best_val_loss")

        hp = d.get("hyperparameters", {})
        result["hyperparameters"].append({
            "version": d["version"],
            "latent_dim": hp.get("latent_dim"),
            "batch_size": hp.get("batch_size"),
            "learning_rate": hp.get("lr"),
            "weight_decay": hp.get("weight_decay"),
            "epochs_max": hp.get("epochs_max"),
            "patience": hp.get("patience"),
            "epochs_trained": d.get("epochs_trained"),
            "total_params": d.get("total_params"),
            "train_duration_s": d.get("train_duration_s"),
            "device": d.get("device"),
            "alphas_learned": d.get("alphas_learned", {}),
        })

        gm_cm = gm.get("cm", {})
        timing = d.get("inference_timing", {})
        result["model_info"].append({
            "version": d["version"],
            "total_params": d.get("total_params"),
            "latent_dim": hp.get("latent_dim"),
            "learning_rate": hp.get("lr"),
            "alphas_learned": d.get("alphas_learned", {}),
            "per_event_us": timing.get("per_event_us"),
            "global_fp": gm_cm.get("fp"),
            "global_fn": gm_cm.get("fn"),
            "global_tp": gm_cm.get("tp"),
            "global_tn": gm_cm.get("tn"),
        })

        # --- NOUVEAU : robustesse (mean / std / cv_pct par métrique) ---
        rob = d.get("robustness", {})
        result["robustness"].append({
            "version": d["version"],
            "f1":        rob.get("f1", {}),
            "precision": rob.get("precision", {}),
            "recall":    rob.get("recall", {}),
            "auc_roc":   rob.get("auc_roc", {}),
        })

        # --- NOUVEAU : timing d'inférence global + par source ---
        result["inference_timing"].append({
            "version": d["version"],
            "per_event_us": timing.get("per_event_us"),
            "total_ms": timing.get("total_ms"),
            "by_source": timing.get("by_source", {}),
        })

        # --- NOUVEAU : séparation reconstruction (autoencodeur) ---
        result["separation"].append({
            "version": d["version"],
            "mse_normal": gm.get("mse_normal"),
            "mse_attack": gm.get("mse_attack"),
            "mse_ratio": gm.get("mse_ratio"),
            "cm": gm_cm,  # tp/fp/fn/tn global pour la matrice de confusion
        })

        # --- NOUVEAU : seuils de décision par source/contexte ---
        result["thresholds"].append({
            "version": d["version"],
            "thresholds": d.get("thresholds", {}),
        })

        # --- NOUVEAU : stats de nettoyage du jeu d'entraînement ---
        result["cleaning"].append({
            "version": d["version"],
            "cleaning_stats": d.get("cleaning_stats", {}),
        })

    all_attacks = set()
    for d in ordered:
        all_attacks.update(d.get("attack_result", {}).keys())
    for atk in sorted(all_attacks):
        series = []
        prev_recall = None
        for d in ordered:
            ar = d.get("attack_result", {}).get(atk, {})
            recall = ar.get("recall")
            series.append({
                "version": d["version"],
                "detected": ar.get("detected"),
                "total": ar.get("total"),
                **_trend(recall, prev_recall, "recall"),
            })
            prev_recall = recall
        result["by_attack"][atk] = series

    all_sources = set()
    for d in ordered:
        all_sources.update(d.get("metrics_by_source", {}).keys())
    for src in sorted(all_sources):
        series = []
        prev = {}
        for d in ordered:
            ms = d.get("metrics_by_source", {}).get(src, {})
            cm = ms.get("cm", {})
            series.append({
                "version": d["version"],
                "precision": _trend(ms.get("precision"), prev.get("precision"), "precision"),
                "recall": _trend(ms.get("recall"), prev.get("recall"), "recall"),
                "f1": _trend(ms.get("f1"), prev.get("f1"), "f1_score"),
                "auc_roc": _trend(ms.get("auc_roc"), prev.get("auc_roc"), "auc_roc"),
                "false_positives": ms.get("false_positives"),
                "false_negatives": ms.get("false_negatives"),
                "cm": cm,
            })
            prev = ms
        result["by_source"][src] = series

    return result


def compare_versions(versions: list[str] | None = None):
    if versions:
        docs = repo.get_many(versions)
        by_version = {d["version"]: d for d in docs}
        ordered = [by_version[v] for v in versions if v in by_version]
    else:
        ordered = repo.get_all_ordered()

    if not ordered:
        return {"versions": [], "comparison_available": False,
                "message": "Aucune version disponible."}

    comparison = _build_comparison(ordered)
    if len(ordered) == 1:
        comparison["message"] = (
            "Une seule version disponible. Le comparatif sera actif "
            "dès le prochain réentraînement du modèle."
        )
    return comparison