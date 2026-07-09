"""
groundtruth.py
==============
AXE 4 (etape 1/2) -- Etiquetage NON CIRCULAIRE des attaques injectees.

PRINCIPE ANTI-CIRCULARITE : les episodes sont etiquetes a partir de SIGNATURES
OBSERVABLES sur les champs ECS BRUTS (chaine de commande, outcome d'auth,
volume brut) -- JAMAIS a partir du score de l'autoencodeur. Le modele ne voit
jamais ces labels ; ils ne servent qu'a l'evaluation. Ainsi "l'AE detecte
l'attaque" n'est pas tautologique.

4 scenarios (identiques au pipeline) :
  1. ssh_bruteforce   T1110.001  (auth)    rafale d'echecs sshd depuis 1 IP
  2. user_creation    T1136.001  (auditd/auth)  useradd / userdel
  3. b64_exec         T1059.004  (auditd)  payload base64 decode -> exec
  4. syslog_burst     --         (syslog)  pic volumetrique

Sortie : groundtruth.json -> liste d'episodes {scenario, mitre, log_source,
host_name, start, end}. On labelle sur TOUT le snapshot ; c'est l'evaluateur
(etape 2) qui restreint au TEST et signale les episodes hors-test.

NUANCE HONNETE : pour les scenarios VOLUMETRIQUES (brute-force, burst), la
signature (compte brut) recoupe une entree du modele -> le label le plus fiable
reste l'HEURE D'INJECTION CONNUE. Renseigne-la dans MANUAL_EPISODES : elle
prime et desactive l'auto-detection du scenario concerne.
"""
from __future__ import annotations
import json
import re

import numpy as np
import pandas as pd

import config as C
import data_loader as DL
import feature_engineering as FE          # _auth_isfail = signal BRUT (outcome/action)

# --- Signatures (SEUILS = definitions d'attaque, PAS des params modele) -----
BF_WINDOW_S    = 300     # fenetre brute-force
BF_MIN_FAILS   = 10      # >= N echecs sshd / IP / fenetre => brute-force
BURST_WINDOW_S = 60      # fenetre pic syslog
BURST_MIN_CNT  = 500     # >= N evenements syslog / hote / fenetre => burst
MERGE_GAP_S    = C.EPISODE_GAP_SECONDS    # fusion d'episodes proches (300s)

USERADD_RE = re.compile(r"\b(useradd|userdel|adduser|deluser)\b", re.I)
B64_RE     = re.compile(r"base64\s+(-d|--decode)|\|\s*base64", re.I)

# Heures d'injection CONNUES (prioritaires). Si tu remplis un scenario ici,
# son auto-detecteur est desactive (ta verite operateur est plus fiable).
MANUAL_EPISODES = [
    # {"scenario": "ssh_bruteforce", "mitre": "T1110.001", "log_source": "auth",
    #  "host_name": "ASUS-X415JA", "start": "2026-..:..Z", "end": "2026-..:..Z"},
]


# ---------------------------------------------------------------------------
def _load():
    df = DL.load_dataset()
    df["_dt"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    return df[df["_dt"].notna()].reset_index(drop=True)


def _col(df, name):
    return df.get(name, pd.Series("", index=df.index)).fillna("").astype(str)


def _merge(wins, gap_s):
    """Fusionne des (start, end) proches (<= gap) en episodes uniques."""
    if not wins:
        return []
    wins = sorted(wins)
    out = [list(wins[0])]
    for s, e in wins[1:]:
        if (s - out[-1][1]).total_seconds() <= gap_s:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return [(s, e) for s, e in out]


def _episode(scenario, mitre, source, host, s, e):
    return {"scenario": scenario, "mitre": mitre, "log_source": source,
            "host_name": host, "start": s, "end": e}


# --- 1. Brute-force SSH : rafale d'echecs par IP ----------------------------
def detect_bruteforce(df):
    d = df[df["log_source"] == "auth"].copy()
    if len(d) == 0:
        return []
    d["_fail"] = FE._auth_isfail(d)                 # BRUT : outcome/action
    d["_host"] = _col(d, "host_name")
    d["_ip"] = _col(d, "source_ip")
    d = d[d["_ip"].str.len() > 0]
    w = np.timedelta64(BF_WINDOW_S, "s")
    eps = []
    for (host, ip), g in d.groupby(["_host", "_ip"], sort=False):
        g = g.sort_values("_dt")
        t = g["_dt"].to_numpy(); f = g["_fail"].to_numpy()
        wins, left, run = [], 0, 0.0
        for right in range(len(g)):
            run += f[right]
            while t[right] - t[left] > w:
                run -= f[left]; left += 1
            if run >= BF_MIN_FAILS:
                wins.append((pd.Timestamp(t[left]), pd.Timestamp(t[right])))
        for s, e in _merge(wins, MERGE_GAP_S):
            eps.append(_episode("ssh_bruteforce", "T1110.001", "auth", host, s, e))
    return eps


# --- 2/3. Signatures de chaine (useradd / base64) ---------------------------
def _detect_text(df, regex, scenario, mitre, default_source):
    text = (_col(df, "cmdline") + " " + _col(df, "process_args") + " "
            + _col(df, "process_executable") + " " + _col(df, "process_name")
            + " " + _col(df, "message"))
    d = df[text.str.contains(regex)].copy()
    if len(d) == 0:
        return []
    d["_host"] = _col(d, "host_name")
    eps = []
    for host, g in d.groupby("_host", sort=False):
        g = g.sort_values("_dt")
        wins = [(pd.Timestamp(x), pd.Timestamp(x)) for x in g["_dt"].to_numpy()]
        src = g["log_source"].mode().iat[0] if len(g) else default_source
        for s, e in _merge(wins, MERGE_GAP_S):
            eps.append(_episode(scenario, mitre, src, host, s, e))
    return eps


# --- 4. Pic volumetrique syslog ---------------------------------------------
def detect_burst(df):
    d = df[df["log_source"] == "syslog"].copy()
    if len(d) == 0:
        return []
    d["_host"] = _col(d, "host_name")
    w = np.timedelta64(BURST_WINDOW_S, "s")
    eps = []
    for host, g in d.groupby("_host", sort=False):
        g = g.sort_values("_dt")
        t = g["_dt"].to_numpy()
        wins, left = [], 0
        for right in range(len(g)):
            while t[right] - t[left] > w:
                left += 1
            if right - left + 1 >= BURST_MIN_CNT:
                wins.append((pd.Timestamp(t[left]), pd.Timestamp(t[right])))
        for s, e in _merge(wins, MERGE_GAP_S):
            eps.append(_episode("syslog_burst", "", "syslog", host, s, e))
    return eps


# ---------------------------------------------------------------------------
def main():
    print("=" * 60)
    print("  GROUNDTRUTH -- etiquetage par signatures brutes (non circulaire)")
    print("=" * 60)
    df = _load()
    print(f"  snapshot charge : {len(df):,} logs (timestamp valide)")

    manual_scen = {e["scenario"] for e in MANUAL_EPISODES}
    eps = [_episode(e["scenario"], e.get("mitre", ""), e.get("log_source", ""),
                    e["host_name"], pd.Timestamp(e["start"]), pd.Timestamp(e["end"]))
           for e in MANUAL_EPISODES]

    if "ssh_bruteforce" not in manual_scen:
        eps += detect_bruteforce(df)
    if "user_creation" not in manual_scen:
        eps += _detect_text(df, USERADD_RE, "user_creation", "T1136.001", "auditd")
    if "b64_exec" not in manual_scen:
        eps += _detect_text(df, B64_RE, "b64_exec", "T1059.004", "auditd")
    if "syslog_burst" not in manual_scen:
        eps += detect_burst(df)

    # ids + serialisation (tri chronologique)
    eps.sort(key=lambda e: (e["scenario"], e["start"]))
    out, per = [], {}
    for e in eps:
        per[e["scenario"]] = per.get(e["scenario"], 0) + 1
        out.append({
            "id": f'{e["scenario"]}_{per[e["scenario"]]:02d}',
            "scenario": e["scenario"], "mitre": e["mitre"],
            "log_source": e["log_source"], "host_name": e["host_name"],
            "start": e["start"].isoformat(), "end": e["end"].isoformat(),
            "duration_s": round((e["end"] - e["start"]).total_seconds(), 1),
        })

    with open("groundtruth.json", "w") as f:
        json.dump({"scenarios": out}, f, indent=2)

    # --- resume par scenario (a VERIFIER avant l'etape 2) ---
    print("\n  Episodes detectes :")
    for scen in ("ssh_bruteforce", "user_creation", "b64_exec", "syslog_burst"):
        g = [o for o in out if o["scenario"] == scen]
        tag = " [MANUEL]" if scen in manual_scen else ""
        print(f"    {scen:16s}: {len(g)} episode(s){tag}")
        for o in g:
            print(f"        {o['id']} | {o['host_name']} | "
                  f"{o['start']} -> {o['end']} ({o['duration_s']}s)")
    print(f"\n  -> groundtruth.json ({len(out)} episodes)")
    print("=" * 60)
    return out


if __name__ == "__main__":
    main()