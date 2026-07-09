"""
feature_engineering.py
=======================
Calcule TOUTES les features numeriques a partir des champs ECS bruts.

Garanties anti-fuite : toutes les features de nouveaute / deviation / sequence
sont CAUSALES (cumcount, expanding().shift(1), rolling temporel borne par le
present, deux-pointeurs sur temps trie). Aucune statistique du futur injectee.

Les nouveautes sont exprimees en RARETE continue rarity = 1/(1+vues) plutot
qu'en binaire is_new : la binaire derive avec la distance au train (le
vocabulaire s'etend en continu) et destabilise la calibration -> reservee a Sigma.
"""
from __future__ import annotations
import math
import re
from collections import defaultdict

import numpy as np
import pandas as pd

import config as C

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_EPS = 1e-9
_EMPTY = ["", "nan", "None", "unknown"]

# Severite syslog (RFC 5424) en ordinal : plus severe = plus grand.
_SEVERITY = {
    "emerg": 7, "emergency": 7, "panic": 7,
    "alert": 6,
    "crit": 5, "critical": 5,
    "err": 4, "error": 4,
    "warn": 3, "warning": 3,
    "notice": 2,
    "info": 1, "informational": 1,
    "debug": 0,
}


# ---------------------------------------------------------------------------
# 1. TIMESTAMP (base de tous les tris/fenetres causales)
# ---------------------------------------------------------------------------
def _add_time(df):
    df["_dt"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    return df


# ---------------------------------------------------------------------------
# 2. FORME DU MESSAGE + is_root + severite + ip externe
# ---------------------------------------------------------------------------
def _severity_ordinal(s):
    lv = s.fillna("").astype(str).str.lower().str.strip()
    return lv.map(_SEVERITY).fillna(1.0).astype(float)


def _add_message(df):
    msg = df["message"].fillna("").astype(str).str.lower()
    length = msg.str.len()
    df["msg_length_log"] = np.where(length > 0, np.log1p(length), 0.0).round(4)
    df["msg_has_ip"]  = msg.str.contains(_IP_RE, regex=True).astype(int)
    df["msg_has_url"] = (msg.str.contains("http://") | msg.str.contains("https://")).astype(int)
    df["is_root"] = (df["user_name"].fillna("").astype(str).str.lower() == "root").astype(int)
    df["log_severity"] = _severity_ordinal(df["log_level"])
    df = _add_ip_external(df)
    return df


def _add_ip_external(df):
    """1 si l'IP source est PUBLIQUE. Prive = 127./10./192.168./172.16-31."""
    ip = df["source_ip"].fillna("").astype(str)
    empty = ip.isin(["", "nan", "None", "::1", "0.0.0.0"])
    priv = ip.str.startswith(("127.", "10.", "192.168."))
    oct2 = pd.to_numeric(ip.str.extract(r"^172\.(\d{1,3})\.", expand=False), errors="coerce")
    priv = priv | oct2.between(16, 31).fillna(False)
    df["ip_is_external"] = (~empty & ~priv).astype(int)
    return df


# ---------------------------------------------------------------------------
# 3. AUDITD : forme de commande (entropie / longueur / nb d'args)
# ---------------------------------------------------------------------------
def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _add_auditd(df):
    args = df["process_args"].fillna("").astype(str)
    cmdline = df["cmdline"].fillna("").astype(str)
    exe = df["process_executable"].fillna("").astype(str)
    cmd = args.where(args.str.len() > 0, cmdline)
    cmd = cmd.where(cmd.str.len() > 0, exe).str.lower()

    clen = cmd.str.len()
    df["cmd_length_log"] = np.where(clen > 0, np.log1p(clen), 0.0).round(4)
    df["arg_count"] = np.where(
        args.str.len() > 0, args.str.split().map(len),
        cmdline.str.split().map(len)).astype(int)
    df["cmd_entropy"] = cmd.map(_shannon_entropy).round(4)
    return df


# ---------------------------------------------------------------------------
# 4. event_type unifie (sert au n-gramme sequentiel)
# ---------------------------------------------------------------------------
_SYSLOG_PREFIX_CAT = [
    (("kernel",), "kernel"),
    (("systemd-timesyncd",), "time"),
    (("systemd-resolved", "systemd-networkd", "avahi", "networkmanager",
      "wpa_supplicant", "dhclient", "dhcpcd"), "network"),
    (("rsyslogd", "syslog-ng"), "logging"),
    (("charon", "ipsec", "strongswan"), "vpn"),
    (("dockerd", "containerd", "runc", "docker"), "container"),
    (("sshd", "sshguard"), "ssh"),
    (("cron", "anacron", "atd"), "scheduler"),
    (("gnome", "gsd-", "gdm", "mutter", "ibus", "tracker", "xdg",
      "evolution", "totem", "at-spi", "gnome-keyring", "code.desktop",
      "vsce-sign", "google-chrome", "snapd-desktop"), "desktop"),
    (("snapd", "dpkg", "apt", "unattended", "packagekit"), "package"),
    (("nginx", "apache", "httpd"), "web"),
    (("systemd-udevd",), "udev"),
    (("systemd-logind",), "session"),
    (("systemd",), "init"),
]


def _syslog_category(prog):
    p = str(prog).lower()
    for prefixes, cat in _SYSLOG_PREFIX_CAT:
        if p.startswith(prefixes):
            return cat
    return "other"


_SYSCALL_CAT = {
    "execve": "exec", "execveat": "exec",
    "open": "file", "openat": "file", "openat2": "file", "read": "file",
    "write": "file", "unlink": "file", "unlinkat": "file", "rename": "file",
    "renameat": "file", "chmod": "file", "chown": "file", "truncate": "file",
    "ftruncate": "file",
    "connect": "network", "bind": "network", "accept": "network",
    "accept4": "network", "socket": "network", "sendto": "network",
    "recvfrom": "network", "listen": "network",
    "ptrace": "ptrace", "init_module": "module", "finit_module": "module",
    "delete_module": "module", "kill": "signal", "tkill": "signal",
    "tgkill": "signal", "clone": "process", "fork": "process",
    "vfork": "process", "clone3": "process", "mprotect": "memory",
    "mmap": "memory", "mmap2": "memory",
}


def _add_event_type(df):
    prog = df["process_name"].fillna("").astype(str).str.lower()
    action = df["event_action"].fillna("").astype(str).str.lower()
    syscall = df["syscall"].fillna("").astype(str).str.lower()
    src = df["log_source"]

    et = pd.Series("other", index=df.index, dtype=object)

    auth_m = src == "auth"
    et.loc[auth_m] = np.where(
        action[auth_m] != "", action[auth_m],
        prog[auth_m].map(lambda p: {"sshd": "ssh", "sudo": "sudo", "su": "su",
                                    "passwd": "passwd"}.get(p, p or "other")))

    sys_m = src == "syslog"
    cat = prog[sys_m].map(_syslog_category)
    sa = action[sys_m]
    et.loc[sys_m] = np.where(sa != "", cat + ":" + sa, cat)

    aud_m = src == "auditd"
    scat = syscall[aud_m].map(lambda s: _SYSCALL_CAT.get(s, "other"))
    aa = action[aud_m]
    et.loc[aud_m] = np.where(aa != "", aa, scat)

    df["event_type"] = et.astype(str)
    return df


# ---------------------------------------------------------------------------
# 5. RARETE CAUSALE (proc / user / geo / syscall / exe / lignee)  -> ponctuel
# ---------------------------------------------------------------------------
def _canonical_proc(name):
    """Corrige deux artefacts REELS des logs syslog :
      * parentheses systemd : '(haveged)' -> 'haveged'
      * troncature TAG a 15 car. : 'gsd-housekeeping'/'gsd-housekeepin' = meme entite."""
    s = str(name).strip()
    if len(s) >= 2 and s[0] == "(" and s[-1] == ")":
        s = s[1:-1]
    s = s.strip("()[]").strip()
    return s[:15]


def _proc_identifier(df):
    """auditd ne peuple souvent PAS process.name -> repli sur basename(executable)."""
    name = df["process_name"].fillna("").astype(str)
    exe = df.get("process_executable", pd.Series("", index=df.index)).fillna("").astype(str)
    exe_base = exe.str.rsplit("/", n=1).str[-1]
    ident = name.where(name != "", exe_base)
    return ident.map(_canonical_proc)


def _resolve_parent_via_pid(df, max_age_s=3600):
    """Reconstruit parent_executable par jointure causale sur le PID (Auditbeat
    ne resout pas process.parent.executable). 100% causal, borne max_age_s
    contre le recyclage des PID."""
    df = df.sort_values("_dt", kind="stable")
    host = df["host_name"].fillna("unknown").astype(str).to_numpy()
    own_pid = (df.get("process_pid", pd.Series("", index=df.index))
               .fillna("").astype(str).str.strip().to_numpy())
    par_pid = (df.get("parent_pid", pd.Series("", index=df.index))
               .fillna("").astype(str).str.strip().to_numpy())
    pname = _proc_identifier(df).astype(str).to_numpy()
    ts = df["_dt"].to_numpy()

    last = {}
    out = np.empty(len(df), dtype=object)
    for i in range(len(df)):
        hit = last.get(host[i] + "|" + par_pid[i]) if par_pid[i] else None
        if hit is not None and (ts[i] - hit[1]) / np.timedelta64(1, "s") <= max_age_s:
            out[i] = hit[0]
        else:
            out[i] = ""
        if own_pid[i]:
            last[host[i] + "|" + own_pid[i]] = (pname[i], ts[i])
    df["parent_executable"] = out.astype(object)
    return df


def _rarity(key_series, valid, counts=None):
    """rarity = 1/(1+vues_avant), causale. En inference live, `counts` prefixe
    les vues du train (continuite). rarity=0 si l'identifiant est invalide."""
    if counts:
        base = key_series.map(counts).fillna(0.0)
    else:
        base = pd.Series(0.0, index=key_series.index)
    seen_before = key_series.groupby(key_series).cumcount() + base
    return np.where(valid.values, 1.0 / (1.0 + seen_before), 0.0)


def _add_novelty(df, novelty_state=None):
    df = df.sort_values("_dt", kind="stable")
    host = df["host_name"].fillna("unknown").astype(str)
    ns = novelty_state or {}

    proc_raw = _proc_identifier(df).astype(str)
    user_raw = df["user_name"].fillna("").astype(str)
    geo_raw  = df["geo_country"].fillna("").astype(str)
    sysc_raw = df.get("syscall", pd.Series("", index=df.index)).fillna("").astype(str).str.lower()
    exe_raw  = df.get("process_executable", pd.Series("", index=df.index)).fillna("").astype(str).str.strip()
    parent_raw = (df.get("parent_executable", pd.Series("", index=df.index))
                  .fillna("").astype(str).str.rsplit("/", n=1).str[-1].map(_canonical_proc))

    proc_valid = ~proc_raw.isin(_EMPTY)
    user_valid = ~user_raw.isin(_EMPTY)
    geo_valid  = ~geo_raw.isin(_EMPTY)
    sysc_valid = ~sysc_raw.isin(_EMPTY)
    exe_valid  = ~exe_raw.isin(_EMPTY)
    lineage_valid = proc_valid & ~parent_raw.isin(_EMPTY)

    proc_key    = host + "|" + proc_raw
    user_key    = host + "|" + user_raw
    geo_key     = geo_raw
    sysc_key    = host + "|" + sysc_raw
    exe_key     = host + "|" + exe_raw
    lineage_key = host + "|" + parent_raw + ">" + proc_raw

    df["proc_rarity"]         = _rarity(proc_key,    proc_valid,    ns.get("proc"))
    df["user_rarity"]         = _rarity(user_key,    user_valid,    ns.get("user"))
    df["geo_rarity"]          = _rarity(geo_key,     geo_valid,     ns.get("geo"))
    df["syscall_rarity"]      = _rarity(sysc_key,    sysc_valid,    ns.get("syscall"))
    df["exe_path_rarity"]     = _rarity(exe_key,     exe_valid,     ns.get("exe"))
    df["parent_child_rarity"] = _rarity(lineage_key, lineage_valid, ns.get("lineage"))
    return df


def build_novelty_state(df):
    """Vocabulaires vus a l'entrainement (a re-injecter en inference live)."""
    host = df["host_name"].fillna("unknown").astype(str)
    proc_key = host + "|" + _proc_identifier(df).astype(str)
    user_key = host + "|" + df["user_name"].fillna("").astype(str)
    geo_key  = df["geo_country"].fillna("").astype(str)
    sysc_key = host + "|" + df.get("syscall", pd.Series("", index=df.index)).fillna("").astype(str).str.lower()
    exe_key  = host + "|" + df.get("process_executable", pd.Series("", index=df.index)).fillna("").astype(str).str.strip()
    parent = (df.get("parent_executable", pd.Series("", index=df.index))
              .fillna("").astype(str).str.rsplit("/", n=1).str[-1].map(_canonical_proc))
    lineage_key = host + "|" + parent + ">" + _proc_identifier(df).astype(str)
    return {
        "proc":    proc_key.value_counts().to_dict(),
        "user":    user_key.value_counts().to_dict(),
        "geo":     geo_key.value_counts().to_dict(),
        "syscall": sysc_key.value_counts().to_dict(),
        "exe":     exe_key.value_counts().to_dict(),
        "lineage": lineage_key.value_counts().to_dict(),
    }


# ---------------------------------------------------------------------------
# 6. AUTH : echec d'auth depuis ECS reel (event.outcome -> repli event.action)
# ---------------------------------------------------------------------------
def _auth_isfail(sub):
    oc = sub["event_outcome"].fillna("").astype(str).str.lower()
    ea = sub["event_action"].fillna("").astype(str).str.lower()
    return np.where(
        oc.eq("failure"), 1.0,
        np.where(oc.eq("success"), 0.0,
                 (ea.str.contains("fail") | ea.str.contains("invalid")).astype(float)))


# ---------------------------------------------------------------------------
# 7. Comptage causal de valeurs DISTINCTES sur fenetre glissante (deux-pointeurs)
#    Sert au password spraying (1 IP -> N users) et credential stuffing
#    (1 user -> N IP), signaux orthogonaux aux comptages de volume.
# ---------------------------------------------------------------------------
def _rolling_distinct_count(frame, key_col, val_col, window_s,
                            empty=("", "nan", "None")):
    """Nb de valeurs DISTINCTES de val_col vues dans (t-window, t], groupe par
    key_col. Causal, O(n). Les valeurs VIDES ne comptent pas comme distinctes :
    un evenement local sans IP (sudo) -> 0 IP distincte, pas 1. Evite le +1
    parasite qui, sur une feature quasi-constante, faisait exploser le z."""
    f = frame[[key_col, val_col, "_dt"]].copy()
    f["_pos"] = np.arange(len(f))
    f = f.sort_values([key_col, "_dt"], kind="stable")
    keys = f[key_col].to_numpy()
    vals = f[val_col].astype(str).to_numpy()
    times = f["_dt"].to_numpy()
    pos = f["_pos"].to_numpy()

    out = np.zeros(len(f), dtype=np.float64)
    w = np.timedelta64(int(window_s), "s")
    empty_set = set(empty)
    counts = defaultdict(int)
    distinct = 0
    left = 0
    for right in range(len(f)):
        if right == 0 or keys[right] != keys[right - 1]:
            counts.clear(); distinct = 0; left = right
        v = vals[right]
        if v not in empty_set:                       # <-- ignore les vides
            if counts[v] == 0:
                distinct += 1
            counts[v] += 1
        while times[right] - times[left] > w:
            lv = vals[left]
            if lv not in empty_set:                  # <-- symetrique a la sortie
                counts[lv] -= 1
                if counts[lv] == 0:
                    distinct -= 1
            left += 1
        out[right] = distinct

    res = np.empty(len(f), dtype=np.float64)
    res[pos] = out
    return res


# ---------------------------------------------------------------------------
# 8. FENETRES GLISSANTES + DEVIATION + SEQUENCE + INTER-ARRIVEE (par source)
# ---------------------------------------------------------------------------
def _add_windows_and_sequence(df):
    out_cols = [
        "event_count_1m_ip", "event_count_5m_ip", "event_count_5m_dev",
        "auth_fail_count_5m", "auth_fail_ratio", "auth_fail_then_success",
        "distinct_users_5m_ip", "distinct_ips_5m_user",
        "et_bigram_rarity", "inter_arrival_log",
    ]
    for c in out_cols:
        df[c] = 0.0
    for c in ("source_ip", "host_name", "process_name", "user_name"):
        df[c] = df[c].fillna("").astype(str)

    for src in C.SOURCES:
        mask = df["log_source"] == src
        if mask.sum() == 0:
            continue
        # Index positionnel propre (unique) puis reaffectation via _orig :
        # deterministe sans dependre de l'unicite de l'index de df.
        sub = df.loc[mask].copy()
        orig_index = sub.index
        sub = sub.reset_index(drop=True)
        sub["_orig"] = orig_index

        if src == "auth":
            ip_ok = ~sub["source_ip"].isin(["", "nan", "None"])
            key = np.where(ip_ok, "ip_" + sub["source_ip"],
                           "host_" + sub["host_name"] + "_" + sub["process_name"])
        else:
            key = "host_" + sub["host_name"].replace("", "unknown")
        sub["_key"] = key

        sub = sub.sort_values(["_key", "_dt"], kind="stable")
        sub["_one"] = 1.0
        g = sub.groupby("_key", sort=False)

        sub["event_count_5m_ip"] = g.rolling("300s", on="_dt")["_one"].count().to_numpy()
        sub["event_count_1m_ip"] = g.rolling("60s",  on="_dt")["_one"].count().to_numpy()

        sub["_lc"] = np.log1p(sub["event_count_5m_ip"].astype(float))
        gk = sub.groupby("_key", sort=False)["_lc"]
        mean_prev = gk.transform(lambda s: s.shift(1).expanding(min_periods=5).mean())
        std_prev = gk.transform(lambda s: s.shift(1).expanding(min_periods=5).std())
        dev = (sub["_lc"] - mean_prev) / (std_prev + _EPS)
        sub["event_count_5m_dev"] = dev.replace([np.inf, -np.inf], 0.0).fillna(0.0)

        # Bigramme sequentiel -> rarete de la transition event_type[t-1]->[t].
        et = sub["event_type"].fillna("other").astype(str)
        prev_et = et.groupby(sub["_key"], sort=False).shift(1).fillna("START")
        bigram = sub["_key"] + "::" + prev_et + ">" + et
        seen_bigram = bigram.groupby(bigram).cumcount()
        n_new_bigram = int((seen_bigram == 0).sum())
        sub["et_bigram_rarity"] = 1.0 / (1.0 + seen_bigram.astype(float))

        # Inter-arrivee (log) par cle : detecteur de rafale robuste aux effets
        # de bord de fenetre. 1re occurrence -> pas de rafale -> gap median.
        iat = sub.groupby("_key", sort=False)["_dt"].diff().dt.total_seconds()
        fill = float(iat.median()) if iat.notna().any() else 0.0
        sub["inter_arrival_log"] = np.log1p(iat.fillna(fill).clip(lower=0.0))

        cols = ["event_count_5m_ip", "event_count_1m_ip", "event_count_5m_dev",
                "et_bigram_rarity", "inter_arrival_log"]

        if src == "auth":
            sub["_isfail"] = _auth_isfail(sub)
            gk2 = sub.groupby("_key", sort=False)
            fail5 = gk2.rolling("300s", on="_dt")["_isfail"].sum().to_numpy()
            tot5  = gk2.rolling("300s", on="_dt")["_one"].count().to_numpy()
            sub["auth_fail_count_5m"] = fail5
            sub["auth_fail_ratio"]    = np.where(tot5 > 0, fail5 / tot5, 0.0)
            isfail = sub["_isfail"].to_numpy()
            fails_before = np.clip(fail5 - isfail, 0, None)
            sub["auth_fail_then_success"] = (1.0 - isfail) * fails_before

            sub["distinct_users_5m_ip"] = _rolling_distinct_count(sub, "_key", "user_name", 300)
            sub["_ukey"] = "u_" + sub["user_name"]
            sub["distinct_ips_5m_user"] = _rolling_distinct_count(sub, "_ukey", "source_ip", 300)

            cols += ["auth_fail_count_5m", "auth_fail_ratio", "auth_fail_then_success",
                     "distinct_users_5m_ip", "distinct_ips_5m_user"]
            nfail = int((sub["auth_fail_count_5m"] > 0).sum())
            print(f"  [FEAT] auth   : fail>0 sur {nfail:,} logs "
                  f"(max fail 5m = {int(sub['auth_fail_count_5m'].max())})")
        else:
            mx = int(sub["event_count_5m_ip"].max()) if len(sub) else 0
            print(f"  [FEAT] {src:6s}: event_count_5m max={mx} | "
                  f"bigrammes nouveaux={n_new_bigram:,}")

        df.loc[sub["_orig"].to_numpy(), cols] = sub[cols].to_numpy()

    return df


# ---------------------------------------------------------------------------
# ORCHESTRATION
# ---------------------------------------------------------------------------
def build_features(df_raw, novelty_state=None):
    """Pipeline complet. Retourne un df enrichi contenant 'log_source',
    '@timestamp' et toutes les features."""
    if len(df_raw) == 0:
        return df_raw.copy()
    df = df_raw.copy()
    df = _add_time(df)
    # @timestamp non parsables (-> NaT) feraient planter groupby().rolling.
    n0 = len(df)
    df = df[df["_dt"].notna()].reset_index(drop=True)
    if n0 - len(df) > 0:
        print(f"  [FEAT] {n0 - len(df):,} logs ecartes (timestamp invalide / NaT)")
    if len(df) == 0:
        return df
    df = _add_message(df)
    df = _add_auditd(df)
    df = _add_event_type(df)
    df = _resolve_parent_via_pid(df)
    df = _add_novelty(df, novelty_state=novelty_state)
    df = df.reset_index(drop=True)
    df = _add_windows_and_sequence(df)

    df["@timestamp"] = df["_dt"]
    df = df.drop(columns=["_dt"]).reset_index(drop=True)

    for f in C.KNOWN_FEATURES:
        if f not in df.columns:
            df[f] = 0.0
        df[f] = pd.to_numeric(df[f], errors="coerce").fillna(0.0)
    return df


def validate_feature_coverage(df):
    """Diagnostic : signale les features entierement nulles (source absente ou
    champ ECS manquant)."""
    print("\n  [VALIDATION] couverture des features :")
    issues = 0
    for s in C.SOURCES:
        d = df[df["log_source"] == s]
        if len(d) == 0:
            print(f"    /!\\ source absente : {s}")
            issues += 1
            continue
        for f in C.FEATURES[s]:
            col = pd.to_numeric(d[f], errors="coerce").fillna(0.0)
            if float(col.abs().sum()) == 0.0:
                print(f"    /!\\ [{s}] feature ENTIEREMENT NULLE : {f}")
                issues += 1
    if issues == 0:
        print("    OK : aucune feature entierement nulle.")
    return issues