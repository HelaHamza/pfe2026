#!/usr/bin/env python3
"""Tests de la couche 3 (LLM + RAG) -- AUCUN appel LLM, AUCUN cout.

Pourquoi zero appel : un test qui depend d'un modele distant n'est pas un
test, c'est une observation. Il change de resultat d'un jour a l'autre et ne
prouve rien devant un jury. Ici, tout ce qui est verifie est deterministe et
rejouable a l'identique : le regroupement en episodes, le retrieval RAG, et
les garde-fous. Le LLM est remplace par des sorties simulees -- y compris des
sorties volontairement fausses, hallucinees ou paresseuses, car c'est
exactement contre ca que les garde-fous existent.

    python test_llm_cnn.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import types

import pandas as pd

import config_llm_cnn as CL
import episode_context_cnn as EC
import triage_cnn as T

# ---------------------------------------------------------------------------
# mini-framework : pas de pytest, pour que ca tourne partout sans installer
# ---------------------------------------------------------------------------
_PASS, _FAIL = [], []


def check(nom: str, condition: bool, detail: str = "") -> None:
    (_PASS if condition else _FAIL).append(nom)
    mark = "  ok  " if condition else " FAIL "
    print(f"[{mark}] {nom}" + (f"\n         -> {detail}" if detail and not condition else ""))


def section(titre: str) -> None:
    print(f"\n\033[1m{titre}\033[0m")


# ---------------------------------------------------------------------------
# fixtures : un CSV d'alertes synthetique reproduisant les scenarios connus
# ---------------------------------------------------------------------------
FIXTURE = [
    # kill chain : chmod -> binaire cache -> persistance crontab (5 s)
    ("2026-07-14T02:11:04Z", "auditd", "asus-x415ja", "root", "chmod",
     "syscall", 12.31, 8.548, "exe_path_rarity"),
    ("2026-07-14T02:11:07Z", "auditd", "asus-x415ja", "root", ".rk_beacon",
     "syscall", 14.88, 8.548, "proc_rarity"),
    ("2026-07-14T02:11:09Z", "auditd", "asus-x415ja", "root", "crontab",
     "syscall", 11.02, 8.548, "proc_rarity"),
    # 400 s plus tard : DOIT devenir un episode distinct (gap = 300 s)
    ("2026-07-14T02:17:49Z", "auditd", "asus-x415ja", "root", "useradd",
     "add_user", 9.90, 8.548, "proc_rarity"),
    # brute-force SSH : 6 echecs -> flag numerique
    *[(f"2026-07-14T03:0{i}:00Z", "auth", "asus-x415ja", f"invaliduser{i}",
       "sshd", "auth_fail", 13.0 + i, 11.109, "is_fail") for i in range(6)],
    # faux positif : rotation des journaux, aucun flag attendu
    ("2026-07-13T23:00:01Z", "auditd", "asus-x415ja", "root", "logrotate",
     "syscall", 10.10, 8.548, "parent_child_rarity"),
    ("2026-07-13T23:00:03Z", "auditd", "asus-x415ja", "root", "gzip",
     "syscall", 9.40, 8.548, "exe_path_rarity"),
]
COLS = ["@timestamp", "log_source", "host_name", "user_name", "process_name",
        "event_type", "mse", "threshold", "top_feat"]


def make_csv() -> str:
    df = pd.DataFrame(FIXTURE, columns=COLS)
    df["source_ip"] = "127.0.0.1"
    df["top_features"] = ""
    path = os.path.join(tempfile.mkdtemp(), "fixture_alerts.csv")
    df.to_csv(path, index=False)
    return path


def fake_ep() -> types.SimpleNamespace:
    return types.SimpleNamespace(
        episode_id="EP-TEST", log_source="auditd", host_name="asus-x415ja",
        start="2026-07-14 02:11:04", end="2026-07-14 02:11:09",
        duration_s=5.0, n_alerts=3, mse_max=14.88, mse_mean=12.7,
        threshold=8.548)


LONG = ("Execution d'un binaire a nom cache suivie d'une persistance crontab "
        "dans la meme fenetre de cinq secondes, precedee d'un chmod.")


# ---------------------------------------------------------------------------
# A. LE TEST D'OR : le LLM et le CNN parlent-ils du meme episode ?
# ---------------------------------------------------------------------------
def oracle_aggregate(df: pd.DataFrame, gap: float) -> int:
    """Re-implementation NAIVE et independante de inference_cnn.aggregate_alerts.

    Volontairement ecrite autrement (boucle explicite, pas de groupby) : si on
    copiait l'implementation testee, le test validerait le bug avec elle.
    """
    df = df.copy()
    df["_ts"] = pd.to_datetime(df["@timestamp"], utc=True)
    n = 0
    for _, g in df.groupby(["log_source", "host_name"]):
        prev = None
        for ts in sorted(g["_ts"]):
            if prev is None or (ts - prev).total_seconds() > gap:
                n += 1
            prev = ts
    return n


def test_episodage(csv: str) -> None:
    section("A. Coherence des episodes (CNN <-> LLM)")
    df = pd.read_csv(csv)
    eps = EC.build_episodes(csv, gap_seconds=CL.EPISODE_GAP_SECONDS)
    attendu = oracle_aggregate(df, CL.EPISODE_GAP_SECONDS)
    check("build_episodes reproduit aggregate_alerts",
          len(eps) == attendu, f"obtenu {len(eps)}, oracle {attendu}")

    ids = {e.episode_id for e in eps}
    check("les episode_id sont uniques", len(ids) == len(eps))

    check("le gap de 300 s coupe la kill chain de useradd",
          any(set(e.processes) >= {"chmod", ".rk_beacon", "crontab"} for e in eps)
          and any("useradd" in e.processes and ".rk_beacon" not in e.processes
                  for e in eps))

    check("tri par mse_max decroissant (pire episode traite en premier)",
          all(eps[i].mse_max >= eps[i + 1].mse_max for i in range(len(eps) - 1)))

    check("aucune alerte perdue au regroupement",
          sum(e.n_alerts for e in eps) == len(df),
          f"{sum(e.n_alerts for e in eps)} vs {len(df)}")


# ---------------------------------------------------------------------------
# B. La politique attrape-t-elle les primitives sensibles ?
# ---------------------------------------------------------------------------
def test_policy(csv: str) -> None:
    section("B. Garde-fous de politique (policy_flags)")
    eps = EC.build_episodes(csv)
    by_proc = lambda p: next(e for e in eps if p in e.processes)  # noqa: E731

    check("binaire cache '.rk_beacon' -> flag",
          any("cache" in f for f in EC.policy_flags(by_proc(".rk_beacon"))))
    check("useradd -> flag processus sensible",
          any("sensible" in f for f in EC.policy_flags(by_proc("useradd"))))
    check("6 echecs is_fail -> flag rafale (seuil = 5)",
          any("rafale" in f for f in EC.policy_flags(by_proc("sshd"))))
    check("logrotate -> AUCUN flag (sinon tout est flague, rien ne l'est)",
          EC.policy_flags(by_proc("logrotate")) == [])


# ---------------------------------------------------------------------------
# C. Les garde-fous resistent-ils a un LLM defaillant ?
# ---------------------------------------------------------------------------
def test_validate() -> None:
    section("C. Resistance a un LLM defaillant (_validate)")
    ep, allowed = fake_ep(), {"T1564.001", "T1053.003"}
    base = {"verdict": "true_positive", "confidence": 0.9, "severity": "high",
            "title": "t", "rationale": LONG, "evidence": ["a", "b"],
            "recommendation": ["isoler"], "kb_refs": ["threat-hidden-exec"]}

    r = T._validate({**base, "verdict": "false_positive"}, ep, allowed,
                    ["binaire a nom cache"])
    check("FP interdit quand un POLICY_FLAG est actif -> uncertain",
          r["verdict"] == "uncertain", r["verdict"])

    r = T._validate({**base, "mitre": [{"technique_id": "T9999.999"}]},
                    ep, allowed, [])
    check("technique MITRE hors KB rejetee (anti-hallucination)",
          r["mitre"] == [] and any("hors KB" in g for g in r["guardrails"]))

    r = T._validate({**base, "verdict": "false_positive", "severity": "info",
                     "rationale": "RAS."}, ep, allowed, [])
    check("cloture sans justification -> uncertain",
          r["verdict"] == "uncertain")

    r = T._validate({**base, "recommendation": [], "evidence": []},
                    ep, allowed, [])
    check("TP sans preuve ni action -> repli injecte, actionable=False",
          r["actionable"] is False and r["recommendation"])

    r = T._validate({**base, "verdict": "banane"}, ep, allowed, [])
    check("verdict hors liste fermee -> uncertain",
          r["verdict"] == "uncertain")

    r = T._validate({**base, "verdict": "uncertain", "confidence": 0.99},
                    ep, allowed, [])
    check("un 'uncertain' ne peut pas etre confiant a 0.99",
          r["confidence"] <= 0.6, str(r["confidence"]))

    r = T._validate({**base, "verdict": "false_positive", "severity": "critical",
                     "rationale": LONG}, ep, allowed, [])
    check("severite 'critical' incoherente avec un FP -> info",
          r["severity"] == "info")

    r = T._validate({}, ep, allowed, [])
    check("reponse LLM vide -> uncertain, jamais de crash",
          r["verdict"] == "uncertain")

    r = T._validate({**base, "kb_refs": []}, ep, allowed, [])
    check("conclusion sans source KB -> signalee non tracable",
          any("tracable" in g for g in r["guardrails"]))


# ---------------------------------------------------------------------------
# D. Le RAG ramene-t-il la bonne fiche ?
# ---------------------------------------------------------------------------
def test_rag(csv: str) -> None:
    section("D. Retrieval (rag_cnn)")
    import rag_cnn
    index = rag_cnn.get_index()
    eps = EC.build_episodes(csv)
    by_proc = lambda p: next(e for e in eps if p in e.processes)  # noqa: E731

    def top_ids(ep):
        return [c.id for c, _ in index.retrieve(ep.rag_query(), ep.keys,
                                                ep.log_source)]

    def ranked(ep):
        """Fiches reellement classees par score.

        ref-features est injecte d'office en tete quel que soit son score :
        il ne participe pas au classement et doit etre exclu, sinon le test
        mesure une constante au lieu de mesurer le retrieval.
        """
        return [i for i in top_ids(ep) if not i.startswith("ref-")]

    check("la KB charge des chunks", len(index.chunks) > 0,
          f"{len(index.chunks)} chunks")
    check("logrotate -> fiche baseline en tete du classement",
          ranked(by_proc("logrotate"))[0] == "baseline-logrotate",
          str(ranked(by_proc("logrotate"))[:3]))
    check("logrotate -> la baseline bat la fiche menace (separation FP/TP)",
          ranked(by_proc("logrotate")).index("baseline-logrotate")
          < ranked(by_proc("logrotate")).index("threat-log-tampering"))
    check("sshd + is_fail -> fiche brute-force retrouvee",
          any("bruteforce" in i for i in top_ids(by_proc("sshd"))))
    check("crontab/.rk_beacon -> fiche persistance retrouvee",
          any("persistence" in i or "hidden" in i
              for i in top_ids(by_proc(".rk_beacon"))))
    check("la fiche _features est toujours injectee",
          any(i.startswith("ref-") for i in top_ids(by_proc("logrotate"))))
    check("allowed_mitre est un ensemble ferme non vide",
          len(index.allowed_mitre) > 0 and
          all(m.startswith("T") for m in index.allowed_mitre))


# ---------------------------------------------------------------------------
# E. Panne LLM : on degrade, on ne perd rien
# ---------------------------------------------------------------------------
def test_fail_open(csv: str) -> None:
    section("E. Fail-open (panne API)")
    import rag_cnn
    from llm_client_cnn import LLMError

    eps = EC.build_episodes(csv)
    ep = eps[0]

    original = T.complete_json
    T.complete_json = lambda *a, **k: (_ for _ in ()).throw(
        LLMError("429 rate limit simule"))
    try:
        r = T.triage_episode(ep, rag_cnn.get_index())
    finally:
        T.complete_json = original

    check("panne LLM -> l'episode survit (jamais supprime)", r is not None)
    check("panne LLM -> verdict 'uncertain', jamais 'false_positive'",
          r["verdict"] == "uncertain", r.get("verdict"))
    check("la cause de la panne est tracee", "429" in str(r))


# ---------------------------------------------------------------------------
# F. Regressions deja corrigees : elles ne doivent pas revenir
# ---------------------------------------------------------------------------
def test_regressions(csv: str) -> None:
    section("F. Non-regression (bugs deja corriges)")
    df = pd.read_csv(csv)
    df.loc[0, "user_name"] = None          # NaN pandas
    p = csv.replace(".csv", "_nan.csv")
    df.to_csv(p, index=False)

    ep = next(e for e in EC.build_episodes(p) if ".rk_beacon" in e.processes)
    dossier = ep.render()
    check("un user_name manquant ne devient pas le fait 'nan'",
          "nan" not in dossier.lower(), dossier[:160])

    check("le gap du LLM est identique a celui du CNN",
          CL.EPISODE_GAP_SECONDS == 300,
          f"gap={CL.EPISODE_GAP_SECONDS} : verifier config_cnn.py")
    check("'false_positive' n'est pas auto-clos par defaut",
          CL.AUTO_CLOSE_ENABLED is False)


# ---------------------------------------------------------------------------
def main() -> int:
    print("Tests couche LLM/RAG -- aucun appel reseau, aucun cout\n" + "=" * 58)
    csv = make_csv()
    test_episodage(csv)
    test_policy(csv)
    test_validate()
    test_rag(csv)
    test_fail_open(csv)
    test_regressions(csv)

    print("\n" + "=" * 58)
    print(f"\033[1m{len(_PASS)} reussis, {len(_FAIL)} echoues\033[0m")
    if _FAIL:
        print("\nEchecs :")
        for f in _FAIL:
            print(f"  - {f}")
        return 1
    print("Architecture validee : garde-fous, RAG et episodage conformes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())