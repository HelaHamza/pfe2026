from __future__ import annotations

"""Trace la figure d'evaluation a partir des sorties de evaluate_cnn_vs_llm.py :
la courbe ROC du CNN + les deux points d'operation (CNN seul, cascade CNN+LLM).

    python3 plot_eval.py        # lit eval_roc_points.csv + eval_summary.json
"""

import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd


def main(roc_csv="eval_roc_points.csv", summary_json="eval_summary.json",
         out="eval_figure.png") -> None:
    pts = pd.read_csv(roc_csv)
    s = json.load(open(summary_json, encoding="utf-8"))

    fig, ax = plt.subplots(figsize=(6.2, 6))
    ax.plot(pts["fpr"], pts["tpr"], "-", color="#2b6cb0", lw=2,
            label=f"CNN -- courbe ROC (AUC={s['cnn_auc']:.3f})")
    ax.plot([0, 1], [0, 1], "--", color="#a0aec0", lw=1, label="hasard (AUC=0.5)")

    c = s["cnn_operating"]
    ax.scatter([c["fpr"]], [c["tpr"]], s=130, color="#dd6b20", zorder=5,
               label=f"CNN @seuil POT (prec={c['precision']:.2f})")
    p = s["pipeline_operating"]
    ax.scatter([p["fpr"]], [p["tpr"]], s=170, marker="*", color="#38a169", zorder=6,
               label=f"CNN+LLM (prec={p['precision']:.2f})")
    ax.annotate("", xy=(p["fpr"], p["tpr"]), xytext=(c["fpr"], c["tpr"]),
                arrowprops=dict(arrowstyle="->", color="#38a169", lw=2))
    ax.text((c["fpr"] + p["fpr"]) / 2, c["tpr"] - 0.06,
            "le LLM retire les FP\n(FPR baisse, TPR constant)",
            ha="center", fontsize=9, color="#276749")

    ax.set_xlabel("Taux de faux positifs (FPR)")
    ax.set_ylabel("Taux de vrais positifs (TPR = rappel)")
    ax.set_title("CNN seul vs cascade CNN+LLM\nmeme rappel, moins de faux positifs")
    ax.set_xlim(-0.03, 1.03)
    ax.set_ylim(-0.03, 1.03)
    ax.legend(loc="lower right", fontsize=8.5)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    print(f"figure ecrite : {out}")


if __name__ == "__main__":
    main()