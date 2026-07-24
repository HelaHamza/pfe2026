# Patch de `config_cnn.py` — isolation du candidat

**C'est la seule modification à apporter à ton code existant.** Elle fait 8 lignes,
elle est rétrocompatible, et `train_eval_cnn.py` reste rigoureusement inchangé.

---

## 1. Bloc « Artifacts » — remplacement

**Chercher** (vers la fin du fichier) :

```python
# --- Artifacts SEPARES (n'ecrasent AUCUN artifact MLP) ----------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH      = os.path.join(_HERE, "model_cnn.pt")
BUNDLE_PATH     = os.path.join(_HERE, "cnn_bundle.pkl")
THRESH_PATH     = os.path.join(_HERE, "cnn_thresholds.pkl")
NOVELTY_STATE_PATH = os.path.join(_HERE, "cnn_novelty_state.pkl")
```

**Remplacer par** :

```python
# --- Artifacts SEPARES (n'ecrasent AUCUN artifact MLP) ----------------------
_HERE = os.path.dirname(os.path.abspath(__file__))

# ARTIFACT_DIR : point d'isolation du reentrainement.
#   * non defini            -> comportement historique, artefacts dans ML/
#   * SENTINEL_ARTIFACT_DIR -> le training ecrit AILLEURS (artifacts/_candidate)
#     et ne touche donc jamais la production tant que le gate n'a pas statue.
# Consequence importante : DATASET_CACHE suit ARTIFACT_DIR. Le cache d'un
# candidat est le snapshot DECONTAMINE prepare par retraining/extract.py, ce
# qui elimine le risque de reentrainer silencieusement sur les donnees du mois
# precedent.
ARTIFACT_DIR = os.getenv("SENTINEL_ARTIFACT_DIR", _HERE)
os.makedirs(ARTIFACT_DIR, exist_ok=True)

MODEL_PATH         = os.path.join(ARTIFACT_DIR, "model_cnn.pt")
BUNDLE_PATH        = os.path.join(ARTIFACT_DIR, "cnn_bundle.pkl")
THRESH_PATH        = os.path.join(ARTIFACT_DIR, "cnn_thresholds.pkl")
NOVELTY_STATE_PATH = os.path.join(ARTIFACT_DIR, "cnn_novelty_state.pkl")
```

---

## 2. Bloc « cache » — déplacement et ancrage

**Chercher** (vers le haut du fichier, sous la section Elasticsearch) :

```python
DATASET_CACHE = "dataset_snapshot.parquet"
USE_CACHE     = True
```

**Supprimer ces deux lignes** et les réintroduire **après** le bloc `ARTIFACT_DIR`
(l'ordre compte : `ARTIFACT_DIR` doit être défini avant) :

```python
# Snapshot du corpus. Chemin ABSOLU et ancre sur ARTIFACT_DIR : un chemin
# relatif dependait du cwd, qui n'est pas le meme sous systemd que dans un
# shell interactif.
DATASET_CACHE = os.path.join(ARTIFACT_DIR, "dataset_snapshot.parquet")
USE_CACHE     = os.getenv("SENTINEL_USE_CACHE", "1") == "1"
```

---

## 3. `SCORED_TEST_CSV` — ancrage (optionnel mais utile)

**Chercher** :

```python
SCORED_TEST_CSV = "cnn_scored_test.csv"
```

**Remplacer par** :

```python
# Ancre lui aussi : le CSV scoré du candidat atterrit dans son propre
# repertoire et devient un artefact d'inspection gratuit apres chaque cycle.
SCORED_TEST_CSV = os.path.join(ARTIFACT_DIR, "cnn_scored_test.csv")
```

---

## Vérification

```bash
cd ML

# 1. Le comportement par defaut est strictement inchange
python -c "import config_cnn as C; print(C.ARTIFACT_DIR); print(C.MODEL_PATH)"
# -> .../ML          et  .../ML/model_cnn.pt

# 2. L'isolation fonctionne
SENTINEL_ARTIFACT_DIR=/tmp/essai python -c \
  "import config_cnn as C; print(C.MODEL_PATH, C.DATASET_CACHE)"
# -> /tmp/essai/model_cnn.pt /tmp/essai/dataset_snapshot.parquet

# 3. Les tests de contrat passent
pytest tests/test_config_contract.py -v
```

---

## Ce que ce patch corrige, blocage par blocage

| Blocage identifié | Mécanisme de correction |
|---|---|
| **B1** — le cache parquet fige les données du mois précédent, sans erreur | Le répertoire du candidat est neuf, donc `DATASET_CACHE` pointe vers le snapshot fraîchement extrait et décontaminé. Le cache passe du statut de bug à celui de point d'injection. |
| **B3** — `train_eval_cnn.py` écrase les artefacts de production | Les 4 `dump` du training suivent `ARTIFACT_DIR` → ils écrivent dans `_candidate/`. `current/` n'est touché qu'après le verdict du gate. |
| Chemin relatif du cache | Ancré en absolu, comme les autres artefacts. |

Les blocages **B2** (fenêtre figée) et **B4** (tout le dataset en RAM) sont traités
hors de `config_cnn.py`, respectivement par `retrain_cnn.compute_window()` et par
`retraining/extract.py`.
