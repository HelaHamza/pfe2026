"""
feature_engineering.py
=======================
Calcule TOUTES les features (numeriques) a partir des champs ECS bruts.

Garanties anti-fuite :
  * Toutes les features de nouveaute / deviation / sequence sont CAUSALES :
    elles n'utilisent que le passe de chaque cle (cumcount, expanding().shift(1),
    rolling temporel borne par le present). Aucune statistique globale calculee
    sur le futur n'est injectee.
  * is_root et isfail sont recalcules depuis les VRAIS champs ECS
    (user.name, event.outcome, event.action) -> corrige le bug ou ces champs
    etaient nuls au niveau ml.* (Logstash avant ingest).

Mapping feature -> type d'anomalie :
  * Ponctuel   : proc_is_new, proc_rarity, user_is_new, geo_is_new,
                 cmd_entropy, cmd_length_log, arg_count, msg_* , ip_is_external
  * Contextuel : hour_sin/cos + is_night + is_weekend croises a is_root,
                 event_count_5m_dev (z-score causal vs baseline de l'entite)
  * Collectif  : et_bigram_new (transition event_type[t-1]->event_type[t]
                 jamais vue pour la cle = n-gramme causal)
"""
from __future__ import annotations
import math
import re
import numpy as np
import pandas as pd

import config as C

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_EPS = 1e-9


# ---------------------------------------------------------------------------
# 1. TEMPS
# ---------------------------------------------------------------------------
def _add_time(df):
    dt = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df["_dt"] = dt
    h = dt.dt.hour.fillna(0).astype(float)
    w = dt.dt.dayofweek.fillna(0).astype(float)   # 0=lundi ... 6=dimanche
    df["hour_sin"]   = np.sin(2 * np.pi * h / 24.0).round(4)
    df["hour_cos"]   = np.cos(2 * np.pi * h / 24.0).round(4)
    df["is_night"]   = ((h >= 22) | (h < 6)).astype(int)
    df["is_weekend"] = (w >= 5).astype(int)
    return df


# ---------------------------------------------------------------------------
# 2. FORME DU MESSAGE + is_root (depuis le VRAI user.name ECS)
# ---------------------------------------------------------------------------
def _add_message(df):
    msg = df["message"].fillna("").astype(str).str.lower()
    length = msg.str.len()
    df["msg_length_log"] = np.where(length > 0, np.log1p(length), 0.0).round(4)
    df["msg_word_count"] = msg.str.split().map(len).astype(int)
    df["msg_has_ip"]   = msg.str.contains(_IP_RE, regex=True).astype(int)
    df["msg_has_url"]  = (msg.str.contains("http://") | msg.str.contains("https://")).astype(int)
    df["msg_has_pipe"] = msg.str.contains(" | ", regex=False).astype(int)
    df["is_root"] = (df["user_name"].fillna("").astype(str).str.lower() == "root").astype(int)
    df = _add_ip_external(df)
    return df


def _add_ip_external(df):
    """ip_is_external (porte du Ruby Logstash) : 1 si l'IP source est PUBLIQUE.
    Prive = 127./10./192.168./172.16-31. ; vide ou ::1 -> 0."""
    ip = df["source_ip"].fillna("").astype(str)
    empty = ip.isin(["", "nan", "None", "::1", "0.0.0.0"])
    priv = ip.str.startswith(("127.", "10.", "192.168."))
    oct2 = ip.str.extract(r"^172\.(\d{1,3})\.", expand=False)
    oct2 = pd.to_numeric(oct2, errors="coerce")
    priv_172 = oct2.between(16, 31).fillna(False)
    priv = priv | priv_172
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
# Categorisation syslog par PREFIXE (robuste a la troncature 15 car. et aux
# variantes). Ordre = du plus specifique au plus general. Les familles sont
# tirees des process_name reellement observes (charon/ipsec, gnome/gsd, snapd,
# code.desktop, vsce-sign, dockerd, avahi, NetworkManager...).
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
    # Bureau / session graphique (avant 'snapd' pour capter snapd-desktop)
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

    # auth
    auth_m = src == "auth"
    auth_et = np.where(
        action[auth_m] != "", action[auth_m],
        prog[auth_m].map(lambda p: {"sshd": "ssh", "sudo": "sudo", "su": "su",
                                    "passwd": "passwd"}.get(p, p or "other")))
    et.loc[auth_m] = auth_et

    # syslog : categorie + action
    sys_m = src == "syslog"
    cat = prog[sys_m].map(_syslog_category)
    sa = action[sys_m]
    et.loc[sys_m] = np.where(sa != "", cat + ":" + sa, cat)

    # auditd : action sinon categorie syscall
    aud_m = src == "auditd"
    scat = syscall[aud_m].map(lambda s: _SYSCALL_CAT.get(s, "other"))
    aa = action[aud_m]
    et.loc[aud_m] = np.where(aa != "", aa, scat)

    df["event_type"] = et.astype(str)
    # syscall_category exploitee par d'eventuelles analyses (non scoree)
    df["syscall_category"] = syscall.map(lambda s: _SYSCALL_CAT.get(s, "other"))
    return df


# ---------------------------------------------------------------------------
# 5. NOUVEAUTE CAUSALE (proc / user / geo jamais vus)  -> ponctuel
#    cumcount sur le df TRIE PAR TEMPS : 0 = toute premiere apparition.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
def _canonical_proc(name):
    """Canonicalise un process_name pour la nouveaute. Corrige deux artefacts
    REELS des logs syslog (pas des bugs de parsing) :
      * parentheses systemd : '(haveged)' -> 'haveged', '(sd-pam)' -> 'sd-pam'
      * troncature TAG syslog a 15 car. : on tronque TOUT a 15 pour que
        'gsd-housekeeping' (complet) et 'gsd-housekeepin' (tronque) soient la
        MEME entite, au lieu de deux fausses nouveautes."""
    s = str(name).strip()
    if len(s) >= 2 and s[0] == "(" and s[-1] == ")":
        s = s[1:-1]
    s = s.strip("()[]").strip()
    return s[:15]


def _proc_identifier(df):
    """Identifiant de processus pour la nouveaute. auditd ne peuple souvent PAS
    process.name -> on retombe sur le basename de process.executable. Puis
    canonicalisation (parentheses + troncature 15 car.)."""
    name = df["process_name"].fillna("").astype(str)
    exe = df.get("process_executable", pd.Series("", index=df.index)).fillna("").astype(str)
    exe_base = exe.str.rsplit("/", n=1).str[-1]      # /usr/bin/curl -> curl
    ident = name.where(name != "", exe_base)
    return ident.map(_canonical_proc)


def _add_novelty(df, novelty_state=None):
    """Si novelty_state est fourni (inference live), on prefixe les compteurs
    avec les comptes deja vus a l'entrainement (continuite)."""
    df = df.sort_values("_dt", kind="stable")
    host = df["host_name"].fillna("unknown").astype(str)

    def _new_and_rarity(key_series, valid, prefix_counts=None):
        # valid = l'identifiant est non vide ; un identifiant vide ne doit
        # JAMAIS etre compte comme "nouveau" (evite un geo_is_new=1 parasite
        # quand le pays est inconnu).
        if prefix_counts is not None:
            base = key_series.map(lambda k: prefix_counts.get(k, 0))
        else:
            base = pd.Series(0, index=key_series.index)
        seen_before = key_series.groupby(key_series).cumcount() + base
        is_new = ((seen_before == 0) & valid.values).astype(int)
        rarity = np.where(valid.values, 1.0 / (1.0 + seen_before), 0.0)
        return is_new, rarity, seen_before

    proc_raw = _proc_identifier(df).astype(str)        # repli executable
    user_raw = df["user_name"].fillna("").astype(str)
    geo_raw  = df["geo_country"].fillna("").astype(str)
    _EMPTY = ["", "nan", "None", "unknown"]
    proc_valid = ~proc_raw.isin(_EMPTY)
    user_valid = ~user_raw.isin(_EMPTY)
    geo_valid  = ~geo_raw.isin(_EMPTY)

    proc_key = host + "|" + proc_raw
    user_key = host + "|" + user_raw
    geo_key  = geo_raw

    pc = (novelty_state or {}).get("proc") if novelty_state else None
    uc = (novelty_state or {}).get("user") if novelty_state else None
    gc = (novelty_state or {}).get("geo") if novelty_state else None

    df["proc_is_new"], df["proc_rarity"], _ = _new_and_rarity(proc_key, proc_valid, pc)
    df["user_is_new"], _, _ = _new_and_rarity(user_key, user_valid, uc)
    df["geo_is_new"], _, _  = _new_and_rarity(geo_key, geo_valid, gc)
    # Lignee parent->enfant : signal host-based fort (un shell lance par un
    # service web = transition jamais vue). Nouveaute causale (cumcount).
    parent_raw = (df.get("parent_executable", pd.Series("", index=df.index))
                  .fillna("").astype(str).str.rsplit("/", n=1).str[-1]
                  .map(_canonical_proc))
    lineage_valid = proc_valid & ~parent_raw.isin(_EMPTY)
    lineage_key = host + "|" + parent_raw + ">" + proc_raw   # parent>enfant
    lc = (novelty_state or {}).get("lineage") if novelty_state else None
    df["parent_child_new"], _, _ = _new_and_rarity(lineage_key, lineage_valid, lc)
    
    return df


def build_novelty_state(df):
    """Vocabulaires vus a l'entrainement (a re-injecter en inference live)."""
    host = df["host_name"].fillna("unknown").astype(str)
    proc_key = host + "|" + _proc_identifier(df).astype(str)
    user_key = host + "|" + df["user_name"].fillna("").astype(str)
    geo_key = df["geo_country"].fillna("").astype(str)
    parent = (df.get("parent_executable", pd.Series("", index=df.index))
              .fillna("").astype(str).str.rsplit("/", n=1).str[-1]
              .map(_canonical_proc))
    lineage_key = host + "|" + parent + ">" + _proc_identifier(df).astype(str)
    return {
        "proc": proc_key.value_counts().to_dict(),
        "user": user_key.value_counts().to_dict(),
        "geo":  geo_key.value_counts().to_dict(),
        "lineage": lineage_key.value_counts().to_dict(),   # <-- NOUVEAU
    }

# ---------------------------------------------------------------------------
# 6. AUTH : echec d'auth depuis ECS reel  (event.outcome -> repli event.action)
# ---------------------------------------------------------------------------
def _auth_isfail(sub):
    oc = sub["event_outcome"].fillna("").astype(str).str.lower()
    ea = sub["event_action"].fillna("").astype(str).str.lower()
    isfail = np.where(
        oc.eq("failure"), 1.0,
        np.where(oc.eq("success"), 0.0,
                 (ea.str.contains("fail") | ea.str.contains("invalid")).astype(float)))
    return isfail


# ---------------------------------------------------------------------------
# 7. FENETRES GLISSANTES + DEVIATION + N-GRAMME (par source)
# ---------------------------------------------------------------------------
def _add_windows_and_sequence(df):
    out_cols = [
        "event_count_1m_ip", "event_count_5m_ip", "event_count_5m_dev",
        "auth_fail_count_5m", "auth_ok_count_5m", "auth_fail_ratio",
        "auth_fail_then_success",
        "et_bigram_new",
    ]
    for c in out_cols:
        df[c] = 0.0

    for c in ("source_ip", "host_name", "process_name"):
        df[c] = df[c].fillna("").astype(str)

    for src in C.SOURCES:
        mask = df["log_source"] == src
        if mask.sum() == 0:
            continue
        # On garde une trace des labels d'origine pour la reaffectation finale,
        # PUIS on donne a sub un index positionnel propre (unique) : cela rend
        # le tri + rolling + assignation totalement deterministes, sans jamais
        # dependre de l'unicite de l'index de df.
        sub = df.loc[mask].copy()
        orig_index = sub.index                      # labels d'origine dans df
        sub = sub.reset_index(drop=True)            # index 0..n-1 propre
        sub["_orig"] = orig_index                   # pour reaffecter a la fin

        if src == "auth":
            ip_ok = ~sub["source_ip"].isin(["", "nan", "None"])
            key = np.where(ip_ok, "ip_" + sub["source_ip"],
                           "host_" + sub["host_name"] + "_" + sub["process_name"])
        else:
            host = sub["host_name"].replace("", "unknown")
            key = "host_" + host
        sub["_key"] = key

        # Tri (cle, temps). L'index reste 0..n-1 (unique) -> .to_numpy()
        # positionnel est SUR ici car on reaffecte ensuite via _orig.
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

        et = sub["event_type"].fillna("other").astype(str)
        prev_et = et.groupby(sub["_key"], sort=False).shift(1).fillna("START")
        bigram = sub["_key"] + "::" + prev_et + ">" + et
        seen_bigram = bigram.groupby(bigram).cumcount()
        sub["et_bigram_new"] = (seen_bigram == 0).astype(float)

        cols = ["event_count_5m_ip", "event_count_1m_ip",
                "event_count_5m_dev", "et_bigram_new"]

        if src == "auth":
            sub["_isfail"] = _auth_isfail(sub)
            gk2 = sub.groupby("_key", sort=False)
            fail5 = gk2.rolling("300s", on="_dt")["_isfail"].sum().to_numpy()
            tot5  = gk2.rolling("300s", on="_dt")["_one"].count().to_numpy()
            sub["auth_fail_count_5m"] = fail5
            sub["auth_ok_count_5m"]   = tot5 - fail5
            sub["auth_fail_ratio"]    = np.where(tot5 > 0, fail5 / tot5, 0.0)
            isfail = sub["_isfail"].to_numpy()
            fails_before = np.clip(fail5 - isfail, 0, None)
            sub["auth_fail_then_success"] = (1.0 - isfail) * fails_before
            cols += ["auth_fail_count_5m", "auth_ok_count_5m",
                     "auth_fail_ratio", "auth_fail_then_success"]
            nfail = int((sub["auth_fail_count_5m"] > 0).sum())
            print(f"  [FEAT] auth   : fail>0 sur {nfail:,} logs "
                  f"(max fail 5m = {int(sub['auth_fail_count_5m'].max())})")
        else:
            mx = int(sub['event_count_5m_ip'].max()) if len(sub) else 0
            print(f"  [FEAT] {src:6s}: event_count_5m max={mx} | "
                  f"bigrammes nouveaux={int(sub['et_bigram_new'].sum()):,}")

        # Reaffectation ALIGNEE via les labels d'origine _orig : on remappe
        # explicitement chaque ligne de sub vers sa ligne dans df. Robuste meme
        # si l'index de df a des doublons.
        df.loc[sub["_orig"].to_numpy(), cols] = sub[cols].to_numpy()

    return df
# ---------------------------------------------------------------------------
# ORCHESTRATION
# ---------------------------------------------------------------------------
def build_features(df_raw, novelty_state=None):
    """Pipeline complet de feature engineering. Retourne un df enrichi
    contenant 'log_source', '@timestamp' (alias _dt) et toutes les features."""
    if len(df_raw) == 0:
        return df_raw.copy()
    df = df_raw.copy()
    df = _add_time(df)
    # Les @timestamp non parsables (-> NaT) feraient planter groupby().rolling
    # ("_dt values must not have NaT"). On les ecarte explicitement, en
    # signalant combien : c'est un diagnostic de qualite des donnees.
    n0 = len(df)
    df = df[df["_dt"].notna()].reset_index(drop=True)
    n_drop = n0 - len(df)
    if n_drop > 0:
        print(f"  [FEAT] {n_drop:,} logs ecartes (timestamp invalide / NaT)")
    if len(df) == 0:
        return df
    df = _add_message(df)
    df = _add_auditd(df)
    df = _add_event_type(df)
    df = _add_novelty(df, novelty_state=novelty_state)
    df = _add_novelty(df, novelty_state=novelty_state)
    df = df.reset_index(drop=True)          # <-- assure un index unique
    df = _add_windows_and_sequence(df)
    df = _add_windows_and_sequence(df)

    # On garde @timestamp pour les splits temporels en aval.
    df["@timestamp"] = df["_dt"]
    df = df.drop(columns=["_dt"]).reset_index(drop=True)

    # Securite : toutes les features connues doivent exister numeriquement.
    for f in C.KNOWN_FEATURES:
        if f not in df.columns:
            df[f] = 0.0
        df[f] = pd.to_numeric(df[f], errors="coerce").fillna(0.0)
    return df


def validate_feature_coverage(df):
    """Diagnostic NON SUPERVISE : signale les features entierement nulles
    (typiquement une source absente ou un champ ECS manquant)."""
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