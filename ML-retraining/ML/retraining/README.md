# Sentinel — Couche CT (ré-entraînement mensuel)

## 1. Le problème que ce module résout

Ré-entraîner un auto-encodeur en détection d'anomalies **non supervisée** n'est
pas un problème d'ordonnancement. C'est un problème d'**empoisonnement du
corpus**.

> Si le corpus de ré-entraînement contient une attaque, le modèle apprend cette
> attaque comme normale et ne la détectera plus jamais. Le système se dégrade
> précisément là où il devrait se renforcer, et sans lever la moindre exception.

Le cron représente 10 % du travail. Les 90 % restants sont la **décontamination**
et le **gate de validation**.

Sentinel dispose déjà de la solution dans son architecture : la couche 3
(Sigma + triage LLM) produit les étiquettes qui nettoient le corpus de la
couche 1. Les épisodes classés `true_positive` sont excisés avant
ré-entraînement. C'est une boucle de rétroaction fermée.

---

## 2. Vocabulaire : CI, CD, CT

Ce ne sont pas des alternatives. CI/CD est un sous-ensemble d'outillage du
MLOps ; ce module implémente le troisième pilier.

| Pilier | Déclencheur | Objet versionné | Où il tourne |
|---|---|---|---|
| **CI** | un commit | code | GitHub Actions (`.github/workflows/ci.yml`) |
| **CD** | un build validé | artefact déployable | symlink `artifacts/current` |
| **CT** | le temps | données + modèle | timer systemd, en local |

Un runner GitHub **ne peut pas** ré-entraîner ce modèle : les données sont dans
un Elasticsearch local et l'entraînement dure des heures sur CPU. D'où la
séparation. En vocabulaire de maturité MLOps, le projet passe du **niveau 0**
(tout manuel) au **niveau 1** (pipeline de training automatisé avec validation).
Le niveau 2 — une CI/CD qui déploie le pipeline lui-même — est hors périmètre
PFE, et c'est une limite qu'il vaut mieux annoncer que subir en question.

---

## 3. Installation

### 3.1 Patch de `config_cnn.py`

Voir `PATCH_config_cnn.md`. Huit lignes, rétrocompatibles.
`train_eval_cnn.py` n'est **pas** modifié.

### 3.2 Dépendances supplémentaires

```bash
pip install pyarrow pymongo pytest
```

`pyarrow` est déjà requis par les `.parquet` existants. `pymongo` est optionnel
(sans lui, seule la quarantaine manuelle alimente la décontamination).

### 3.3 Golden set — l'étape manuelle indispensable

```bash
cd ML
python -m retraining.build_golden          # écrit les gabarits, puis s'arrête
$EDITOR golden/incidents.json              # tes scénarios, depuis groundtruth.json
$EDITOR golden/reference.json              # une semaine bénigne, sans incident
python -m retraining.build_golden --from dataset_snapshot.parquet
python -m retraining.build_golden --verify
```

Sans golden set, le gate refuse tout candidat : c'est volontaire. Un
ré-entraînement automatique sans test de non-régression est un mécanisme de
dégradation automatique.

### 3.4 Première version de référence

```bash
mkdir -p artifacts/2026-07-01
cp model_cnn.pt cnn_bundle.pkl cnn_thresholds.pkl \
   cnn_novelty_state.pkl dataset_snapshot.parquet artifacts/2026-07-01/
ln -sfn 2026-07-01 artifacts/current
python -m retraining.artifact_store --status
```

Puis faire pointer `predict_cnn.py` sur `artifacts/current/` — via
`SENTINEL_ARTIFACT_DIR=$(pwd)/artifacts/current` dans son unité de service,
ce qui ne demande aucune modification de code grâce au patch.

### 3.5 Timer

```bash
sudo cp deploy/sentinel-retrain.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-retrain.timer
systemctl list-timers sentinel-retrain
```

---

## 4. Exploitation

```bash
# état du store
python -m retraining.artifact_store --status

# répétition générale, sans entraîner (≈ 10 min)
python -m retraining.retrain_cnn --dry-run

# cycle complet manuel
python -m retraining.retrain_cnn

# rejouer le gate sur un candidat déjà entraîné
python -m retraining.validation_gate --candidate artifacts/_candidate

# retour arrière immédiat
python -m retraining.artifact_store --rollback

# quels incidents seraient excisés ?
python -m retraining.decontaminate --check dataset_snapshot.parquet

# journaux
journalctl -u sentinel-retrain -f
```

**Codes de sortie de `retrain_cnn`** : `0` promu · `2` refusé par le gate
(fonctionnement normal, `SuccessExitStatus` le prend en compte) · `1` erreur.

---

## 5. Le jeu d'artefacts est atomique

Le modèle Sentinel n'est pas `model_cnn.pt`. C'est un quintuplet indissociable :

```
model_cnn.pt              poids
cnn_bundle.pkl            scalers / vocabulaires / features
cnn_novelty_state.pkl     comptes de rareté gelés
cnn_thresholds.pkl        seuils GPD-POT
dataset_snapshot.parquet  corpus (traçabilité)
```

Un `.pt` neuf associé à un `novelty_state` ancien produit un modèle
**silencieusement faux** : la rareté est calculée avec des comptes périmés, la
distribution d'entrée se décale, aucune exception n'est levée. D'où le
versioning par répertoire daté et la bascule par symlink atomique — jamais
fichier par fichier.

---

## 6. Le gate — cinq tests bloquants

| # | Test | Ce qu'il attrape |
|---|---|---|
| 1 | **Intégrité** | artefact manquant, hash divergent, bundle et `.pt` désynchronisés |
| 2 | **Golden set** | régression fonctionnelle : un scénario d'attaque connu n'est plus détecté |
| 3 | **Taux d'alerte** | explosion (bug, dérive massive) ou effondrement à 0 (collapse de l'AE) |
| 4 | **Distribution** | changement de régime des scores (KS) |
| 5 | **Seuils POT** | seuil aberrant ou d'un ordre de grandeur inattendu |

Échec ⇒ le candidat part dans `artifacts/_rejected/`, un rapport JSON est écrit,
`current` ne bouge pas. **Fail-safe, pas fail-open** : un modèle périmé détecte
encore, un modèle cassé ne détecte plus rien.

### Note méthodologique sur le test 4

Le seuillage porte sur la **statistique D** de Kolmogorov-Smirnov, pas sur la
p-value. À N ≈ 10⁵, la p-value est quasi toujours inférieure à 10⁻¹⁰ même pour
un écart négligeable : le test dégénérerait en refus systématique. D mesure
l'écart maximal entre les CDF empiriques, est borné dans [0, 1] et ne dépend
pas de N. La p-value reste calculée sur sous-échantillon, à titre indicatif.

---

## 7. Limites assumées

À énoncer soi-même en soutenance plutôt qu'à les découvrir en question.

1. **Artefact de raboutement.** L'excision retire des lignes avant le
   fenêtrage : les fenêtres qui enjambent la coupure portent un
   `inter_arrival_log` artificiel. Effet borné à W−1 = 15 fenêtres par
   incident, et biaisé vers le **haut** — donc dans le sens conservateur.
2. **Décontamination limitée par le rappel de la couche 3.** Une attaque que
   ni Sigma ni le LLM n'ont vue reste dans le corpus. Le système ne peut pas
   nettoyer ce qu'il n'a pas détecté ; c'est une limite structurelle de toute
   boucle de rétroaction, pas un défaut d'implémentation.
3. **Pas de détection de dérive automatique.** Le déclencheur est temporel, pas
   statistique. Une dérive brutale en milieu de mois attend le cycle suivant.
4. **Pas de MLflow ni de registry.** L'historique des métriques vit dans les
   `manifest.json` et les rapports de gate. Suffisant pour comparer six cycles,
   insuffisant pour une équipe.
5. **Aucun test de charge.** Le comportement au-delà de ~10⁶ événements par
   fenêtre n'a pas été mesuré.

---

## 8. Ce qu'il faut savoir répondre

**« Pourquoi ne pas simplement relancer le training tous les mois ? »**
Parce que le corpus de production contient les attaques que le système a
subies. Ré-entraîner dessus les rend invisibles pour toujours. La
décontamination par les verdicts de la couche 3 est le cœur du dispositif ; le
timer n'en est que le déclencheur.

**« Et si le nouveau modèle est moins bon ? »**
Il n'est jamais promu : le gate le refuse et `current` ne bouge pas. Le
scénario coûteux n'est pas « le candidat est mauvais », c'est « le candidat est
mauvais et on ne s'en aperçoit pas ». Le test golden est là pour ça.

**« Pourquoi systemd plutôt que cron ? »**
`Persistent=true` rattrape l'exécution manquée — un portable est rarement
allumé le 1er à 02:00, et cron aurait sauté le mois en silence. Plus
`MemoryMax` (impossible avec cron), la journalisation centralisée, et
`systemctl start` pour déclencher une démonstration dans exactement le même
environnement que l'exécution automatique.

**« Pourquoi le training tourne-t-il dans un sous-processus ? »**
Isolation des artefacts, restitution complète de la mémoire avant que le gate
ne charge deux modèles, et surtout : `train_eval_cnn.py` reste inchangé. Le
pipeline validé en soutenance n'est pas touché par ce chantier.
