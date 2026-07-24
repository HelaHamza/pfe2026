"""
artifact_store.py
=================
Gestion du jeu d'artefacts CNN comme UNITE ATOMIQUE.

POURQUOI CE MODULE EXISTE
-------------------------
Le modele Sentinel n'est pas `model_cnn.pt`. C'est un quintuplet indissociable :

    model_cnn.pt            poids du reseau
    cnn_bundle.pkl          scalers / vocabulaires / listes de features
    cnn_novelty_state.pkl   comptes de rarete GELES a l'entrainement
    cnn_thresholds.pkl      seuils GPD-POT
    dataset_snapshot.parquet  corpus d'entrainement (tracabilite)

Un `model_cnn.pt` neuf associe a un `cnn_novelty_state.pkl` ancien produit un
modele SILENCIEUSEMENT FAUX : les features de rarete sont calculees avec des
comptes perimes, la distribution d'entree se decale, les scores derivent, et
AUCUNE exception n'est levee. C'est le mode de panne le plus couteux d'un
systeme de detection : il ne tombe pas, il ment.

D'ou : versioning par REPERTOIRE DATE, jamais fichier par fichier, et bascule
par symlink atomique.

    ML/artifacts/
    |-- 2026-07-01/            les 5 fichiers + manifest.json + metrics.json
    |-- 2026-08-01/
    |-- _candidate/            zone de travail du cycle en cours
    |-- _rejected/2026-08-01/  candidats refuses (conserves, jamais rm)
    |-- _reports/              rapports de gate
    `-- current -> 2026-08-01  <= la SEULE chose que predict_cnn.py lit

CLI
---
    python -m retraining.artifact_store --status
    python -m retraining.artifact_store --list
    python -m retraining.artifact_store --verify artifacts/2026-08-01
    python -m retraining.artifact_store --rollback 2026-07-01
    python -m retraining.artifact_store --gc
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from retraining import retrain_config as RC

# --- Composition du jeu d'artefacts -----------------------------------------
MODEL_FILES = (
    "model_cnn.pt",
    "cnn_bundle.pkl",
    "cnn_thresholds.pkl",
    "cnn_novelty_state.pkl",
)
SNAPSHOT_FILE = "dataset_snapshot.parquet"
REQUIRED_FILES = MODEL_FILES + (SNAPSHOT_FILE,)

MANIFEST_NAME = "manifest.json"
METRICS_NAME = "metrics.json"


# ===========================================================================
# 1. Chemins
# ===========================================================================
def artifacts_root() -> Path:
    p = Path(RC.ARTIFACTS_ROOT)
    p.mkdir(parents=True, exist_ok=True)
    return p


def candidate_dir() -> Path:
    return artifacts_root() / RC.CANDIDATE_DIRNAME


def rejected_root() -> Path:
    return artifacts_root() / RC.REJECTED_DIRNAME


def reports_dir() -> Path:
    p = Path(RC.REPORTS_DIR)
    p.mkdir(parents=True, exist_ok=True)
    return p


def current_link() -> Path:
    return artifacts_root() / RC.CURRENT_LINKNAME


def current_dir() -> Path | None:
    """Repertoire actuellement servi, ou None si aucune version promue."""
    link = current_link()
    if not link.is_symlink():
        return None
    resolved = link.resolve()
    return resolved if resolved.is_dir() else None


def current_version() -> str | None:
    d = current_dir()
    return d.name if d else None


def list_versions() -> list[str]:
    """Versions promues, triees chronologiquement (nom = date ISO)."""
    root = artifacts_root()
    out = []
    for child in root.iterdir():
        if child.is_dir() and not child.name.startswith("_") \
                and not child.is_symlink():
            out.append(child.name)
    return sorted(out)


def new_version_id(now: datetime | None = None) -> str:
    """Identifiant de version = date du cycle. Suffixe si collision."""
    now = now or datetime.now(timezone.utc)
    base = now.strftime("%Y-%m-%d")
    root = artifacts_root()
    if not (root / base).exists():
        return base
    for i in range(2, 100):
        cand = f"{base}_{i}"
        if not (root / cand).exists():
            return cand
    raise RuntimeError(f"Impossible d'allouer une version pour {base}")


# ===========================================================================
# 2. Empreintes et manifest
# ===========================================================================
def sha256_file(path: os.PathLike, block: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_commit() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=RC.ML_ROOT, capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or None
    except Exception:
        return None


def _config_fingerprint() -> dict:
    """Empreinte des hyperparametres qui definissent le MODELE.

    Deux versions avec des empreintes differentes ne sont pas comparables :
    une variation de performance vient alors du changement d'hyperparametre,
    pas de la derive des donnees. C'est ce qui rend un historique de metriques
    interpretable sur plusieurs mois.
    """
    import config_cnn as C
    payload = {
        "WINDOW_SIZE": C.WINDOW_SIZE,
        "WINDOW_STRIDE": C.WINDOW_STRIDE,
        "EMBED_DIM": C.EMBED_DIM,
        "CNN_FEATURES": {k: list(v) for k, v in sorted(C.CNN_FEATURES.items())},
        "LATENT_DIM_BY_SOURCE": dict(sorted(C.LATENT_DIM_BY_SOURCE.items())),
        "CONV_CHANNELS": list(C.CONV_CHANNELS),
        "POOL_LEN": C.POOL_LEN,
        "KERNEL_SIZE": C.KERNEL_SIZE,
        "DROPOUT": C.DROPOUT,
        "DENOISE_MASK_FRAC": C.DENOISE_MASK_FRAC,
        "HUBER_DELTA": C.HUBER_DELTA,
        "TOKEN_LOSS_WEIGHT": C.TOKEN_LOSS_WEIGHT,
        "SCORE_LSE_TAU_BY_SOURCE": dict(sorted(C.SCORE_LSE_TAU_BY_SOURCE.items())),
        "POT_TARGET_RATE_BY_SOURCE": dict(sorted(C.POT_TARGET_RATE_BY_SOURCE.items())),
        "POT_INIT_Q": C.POT_INIT_Q,
        "POT_XI_MIN": C.POT_XI_MIN,
        "POT_XI_MAX": C.POT_XI_MAX,
        "EPISODE_GAP_SECONDS": C.EPISODE_GAP_SECONDS,
        "SEED": C.SEED,
    }
    blob = json.dumps(payload, sort_keys=True).encode()
    return {"hash": hashlib.sha256(blob).hexdigest()[:16], "params": payload}


def _versions() -> dict:
    out = {"python": sys.version.split()[0]}
    for mod in ("torch", "numpy", "pandas", "scipy", "sklearn", "pyarrow"):
        try:
            out[mod] = __import__(mod).__version__
        except Exception:
            out[mod] = None
    return out


def write_manifest(d: os.PathLike, meta: dict | None = None) -> dict:
    """Ecrit manifest.json : hashes + provenance + empreinte de config."""
    d = Path(d)
    files = {}
    for name in REQUIRED_FILES:
        p = d / name
        if p.exists():
            files[name] = {"sha256": sha256_file(p), "bytes": p.stat().st_size}
    manifest = {
        "schema": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hostname": os.uname().nodename,
        "git_commit": _git_commit(),
        "versions": _versions(),
        "config_fingerprint": _config_fingerprint(),
        "files": files,
        **(meta or {}),
    }
    _atomic_write_json(d / MANIFEST_NAME, manifest)
    return manifest


def read_manifest(d: os.PathLike) -> dict | None:
    p = Path(d) / MANIFEST_NAME
    if not p.exists():
        return None
    with open(p) as f:
        return json.load(f)


def _atomic_write_json(path: os.PathLike, obj) -> None:
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, default=str)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# ===========================================================================
# 3. Verifications d'integrite
# ===========================================================================
def verify_hashes(d: os.PathLike) -> list[str]:
    """Recalcule les SHA-256 et compare au manifest. Retourne les problemes."""
    d = Path(d)
    man = read_manifest(d)
    if man is None:
        return [f"{d.name}: manifest.json absent"]
    problems = []
    for name, rec in man.get("files", {}).items():
        p = d / name
        if not p.exists():
            problems.append(f"{name}: present au manifest mais absent du disque")
            continue
        actual = sha256_file(p)
        if actual != rec["sha256"]:
            problems.append(
                f"{name}: SHA-256 divergent "
                f"(manifest={rec['sha256'][:12]}... disque={actual[:12]}...)")
    return problems


def check_artifact_set(d: os.PathLike, require_snapshot: bool = True) -> list[str]:
    """Verifie que les 5 artefacts forment un ENSEMBLE COHERENT.

    Ce test est volontairement bete. Il aurait intercepte plusieurs bugs deja
    rencontres sur ce projet : dimensions de features desynchronisees entre le
    bundle et le .pt, seuil manquant pour une source, vocabulaire incoherent
    avec vocab_sizes.
    """
    import joblib
    import torch

    import config_cnn as C

    d = Path(d)
    problems: list[str] = []

    # --- presence et non-vacuite ------------------------------------------
    needed = REQUIRED_FILES if require_snapshot else MODEL_FILES
    for name in needed:
        p = d / name
        if not p.exists():
            problems.append(f"{name}: absent")
        elif p.stat().st_size == 0:
            problems.append(f"{name}: fichier vide")
    if problems:
        return problems

    # --- chargement --------------------------------------------------------
    try:
        state = torch.load(d / "model_cnn.pt", map_location="cpu",
                           weights_only=False)
    except Exception as e:
        return [f"model_cnn.pt: chargement impossible ({e})"]
    try:
        bundle = joblib.load(d / "cnn_bundle.pkl")
        thresholds = joblib.load(d / "cnn_thresholds.pkl")
        novelty = joblib.load(d / "cnn_novelty_state.pkl")
    except Exception as e:
        return [f"artefacts joblib: chargement impossible ({e})"]

    # --- sources : le .pt et le bundle parlent-ils du meme modele ? --------
    pt_sources = {k.split(".")[1] for k in state.keys()
                  if k.startswith("nets.") and len(k.split(".")) > 2}
    bundle_sources = set(bundle.get("scalar_dims", {}))
    if pt_sources and pt_sources != bundle_sources:
        problems.append(
            f"sources desynchronisees : model_cnn.pt={sorted(pt_sources)} "
            f"vs cnn_bundle.pkl={sorted(bundle_sources)}")

    # --- fenetre -----------------------------------------------------------
    if bundle.get("win") != C.WINDOW_SIZE:
        problems.append(
            f"win : bundle={bundle.get('win')} vs config_cnn.WINDOW_SIZE="
            f"{C.WINDOW_SIZE}")

    # --- coherence par source ---------------------------------------------
    for s in bundle_sources:
        feats = list(bundle["feats"].get(s, []))
        expected = list(C.CNN_FEATURES.get(s, []))
        if feats != expected:
            problems.append(
                f"[{s}] liste de features divergente : bundle={feats} "
                f"vs config_cnn={expected}")
        if bundle["scalar_dims"].get(s) != len(feats):
            problems.append(
                f"[{s}] scalar_dims={bundle['scalar_dims'].get(s)} != "
                f"len(feats)={len(feats)}")

        vocab = bundle.get("vocabs", {}).get(s, {})
        expect_vs = C.FIRST_TOKEN_ID + len(vocab)
        if bundle.get("vocab_sizes", {}).get(s) != expect_vs:
            problems.append(
                f"[{s}] vocab_sizes={bundle.get('vocab_sizes', {}).get(s)} != "
                f"FIRST_TOKEN_ID + len(vocab)={expect_vs}")

        scaler = bundle.get("scalers", {}).get(s)
        n_in = getattr(scaler, "n_features_in_", None)
        if n_in is not None and int(n_in) != len(feats):
            problems.append(
                f"[{s}] scaler.n_features_in_={n_in} != len(feats)={len(feats)}")

        # Verification best-effort de l'embedding : premiere dimension du
        # premier tenseur 2-D nomme '*embed*' sous nets.<s>.
        for k, t in state.items():
            if k.startswith(f"nets.{s}.") and "embed" in k.lower() \
                    and hasattr(t, "shape") and len(t.shape) == 2:
                if int(t.shape[0]) != expect_vs:
                    problems.append(
                        f"[{s}] embedding {k} shape[0]={int(t.shape[0])} != "
                        f"vocab_size={expect_vs}")
                break

        if s not in thresholds:
            problems.append(f"[{s}] aucun seuil dans cnn_thresholds.pkl")
        else:
            thr = thresholds[s]
            thr = thr["threshold"] if isinstance(thr, dict) else thr
            if not (isinstance(thr, (int, float)) and thr > 0
                    and thr != float("inf")):
                problems.append(f"[{s}] seuil non exploitable : {thr!r}")

    # --- novelty_state -----------------------------------------------------
    if not isinstance(novelty, dict) or not novelty:
        problems.append("cnn_novelty_state.pkl : vide ou de type inattendu")
    else:
        empty = [k for k, v in novelty.items() if not len(v)]
        if empty:
            problems.append(f"novelty_state : tables vides {empty}")

    return problems


# ===========================================================================
# 4. Promotion / rejet / rollback
# ===========================================================================
def _fsync_dir(path: os.PathLike) -> None:
    fd = os.open(str(path), os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_symlink(target_name: str, link: Path) -> None:
    """Bascule atomique du symlink.

    rename(2) sur un symlink est atomique sur POSIX : a aucun instant
    `current` ne pointe dans le vide. Une inference qui demarre pendant la
    bascule voit soit l'ancienne version, soit la nouvelle, jamais un etat
    intermediaire. La cible est RELATIVE pour que l'arborescence reste
    deplacable.
    """
    if link.exists() and not link.is_symlink():
        raise RuntimeError(
            f"{link} existe et n'est PAS un symlink. Bascule refusee : "
            f"deplace ce repertoire a la main avant de continuer.")
    tmp = link.parent / f".{link.name}.tmp.{os.getpid()}"
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    os.symlink(target_name, tmp, target_is_directory=True)
    os.replace(tmp, link)          # <- atomique
    _fsync_dir(link.parent)


def promote(cand: os.PathLike, version: str, meta: dict | None = None) -> Path:
    """Promeut le candidat : deplacement puis bascule atomique de `current`.

    Ordre imperatif : le repertoire est d'abord entierement en place, ENSUITE
    seulement le symlink bascule. L'inverse laisserait une fenetre pendant
    laquelle `current` pointe vers un repertoire incomplet.
    """
    cand = Path(cand)
    dest = artifacts_root() / version
    if dest.exists():
        raise RuntimeError(f"La version {version} existe deja : {dest}")

    problems = check_artifact_set(cand)
    if problems:
        raise RuntimeError("Promotion refusee, artefacts incoherents :\n  - "
                           + "\n  - ".join(problems))

    write_manifest(cand, {**(meta or {}), "version": version,
                          "status": "promoted"})
    shutil.move(str(cand), str(dest))
    _fsync_dir(artifacts_root())
    _atomic_symlink(version, current_link())
    return dest


def reject(cand: os.PathLike, version: str, reason: dict | str) -> Path:
    """Archive un candidat refuse. JAMAIS de suppression (doctrine projet)."""
    cand = Path(cand)
    rejected_root().mkdir(parents=True, exist_ok=True)
    dest = rejected_root() / version
    n = 2
    while dest.exists():
        dest = rejected_root() / f"{version}_{n}"
        n += 1
    write_manifest(cand, {"version": version, "status": "rejected",
                          "rejection": reason})
    shutil.move(str(cand), str(dest))
    return dest


def rollback(version: str | None = None) -> Path:
    """Repointe `current` vers une version anterieure. Une seule commande."""
    versions = list_versions()
    if not versions:
        raise RuntimeError("Aucune version promue : rollback impossible.")
    if version is None:
        cur = current_version()
        prior = [v for v in versions if v != cur]
        if not prior:
            raise RuntimeError("Une seule version disponible : rien a annuler.")
        version = prior[-1]
    dest = artifacts_root() / version
    if not dest.is_dir():
        raise RuntimeError(f"Version inconnue : {version}")
    problems = check_artifact_set(dest, require_snapshot=False)
    if problems:
        raise RuntimeError(
            f"Rollback refuse, la version {version} est elle-meme incoherente :"
            "\n  - " + "\n  - ".join(problems))
    _atomic_symlink(version, current_link())
    return dest


def reset_candidate() -> Path:
    """Repartir d'une zone de travail propre. Un ancien _candidate est
    archive dans _rejected/ plutot que supprime."""
    cand = candidate_dir()
    if cand.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S")
        reject(cand, f"orphan_{stamp}", "candidat orphelin d'un cycle interrompu")
    cand.mkdir(parents=True, exist_ok=True)
    return cand


# ===========================================================================
# 5. CLI
# ===========================================================================
def _status() -> int:
    root = artifacts_root()
    cur = current_version()
    print(f"racine        : {root}")
    print(f"current       : {cur or '(aucune)'}")
    versions = list_versions()
    print(f"versions      : {len(versions)}")
    for v in versions:
        man = read_manifest(root / v) or {}
        fp = (man.get("config_fingerprint") or {}).get("hash", "?")
        mark = " <= current" if v == cur else ""
        print(f"  - {v}  cfg={fp}  cree={man.get('created_at', '?')[:19]}{mark}")
    if cur:
        problems = check_artifact_set(root / cur, require_snapshot=False) \
            + verify_hashes(root / cur)
        print("integrite     : " + ("OK" if not problems else "PROBLEMES"))
        for p in problems:
            print(f"  ! {p}")
        return 0 if not problems else 1
    return 0


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Store d'artefacts Sentinel CNN")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--status", action="store_true")
    g.add_argument("--list", action="store_true")
    g.add_argument("--verify", metavar="DIR")
    g.add_argument("--rollback", nargs="?", const="__PREVIOUS__",
                   default=None, metavar="VERSION")
    g.add_argument("--gc", action="store_true")
    a = ap.parse_args(argv)

    if a.status:
        return _status()
    if a.list:
        for v in list_versions():
            print(v)
        return 0
    if a.verify:
        problems = check_artifact_set(a.verify) + verify_hashes(a.verify)
        if problems:
            print("PROBLEMES :")
            for p in problems:
                print(f"  - {p}")
            return 1
        print("OK : jeu d'artefacts coherent et non altere.")
        return 0
    if a.gc:
        versions = list_versions()
        old = versions[:-RC.KEEP_LAST_N_VERSIONS] if \
            len(versions) > RC.KEEP_LAST_N_VERSIONS else []
        if not old:
            print("Rien a archiver.")
            return 0
        print("Versions candidates a l'archivage (AUCUNE suppression "
              "automatique, doctrine `mv` jamais `rm`) :")
        for v in old:
            size = sum(f.stat().st_size for f in (artifacts_root() / v).rglob("*")
                       if f.is_file())
            print(f"  - {v}  ({size / 1e6:.0f} Mo)")
        return 0
    if a.rollback is not None:
        target = None if a.rollback == "__PREVIOUS__" else a.rollback
        dest = rollback(target)
        print(f"current -> {dest.name}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
