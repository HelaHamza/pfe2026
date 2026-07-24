# Sentinel - Couche 3 : triage LLM + RAG (branche CNN)

## Ou cette couche se place

```
Auditbeat / Filebeat -> ELK -> data_loader
                                   |
        [COUCHE 1]  cnn_features -> cnn_windowing -> PerSourceHybridConvAE
                    score de RARETE (LSE) -> GPD-POT -> is_alert
                                   |
        [COUCHE 2]  aggregate_alerts : 234 alertes -> 46 EPISODES
                                   |
        [COUCHE 3]  triage_cnn.py  <-- CE MODULE
                    dossier d'episode -> RAG hybride -> LLM -> verdict JSON
                                   |
                    cnn_triage.jsonl / cnn_triaged_episodes.csv -> dashboard
```

Frontiere de responsabilite (a defendre au jury) :
le CNN mesure la **rarete statistique**, le LLM tranche le **sens**.
Le plateau d'inversion des scores (max benin ~ max attaque) n'est pas un defaut
du CNN : c'est la preuve que la discrimination semantique ne peut PAS venir de
la reconstruction. Cette couche est la reponse architecturale a ce constat.

## Fichiers

| Fichier | Role |
|---|---|
| `config_llm_cnn.py` | config autonome (modele, RAG, garde-fous) |
| `kb/baseline/*.md` | profil benin du poste (logrotate, cups, snapd, dnsmasq, GNOME) |
| `kb/threats/*.md` | signatures d'attaque + MITRE + `_features.md` (semantique des features) |
| `rag_cnn.py` | retriever hybride lexical + semantique |
| `episode_context_cnn.py` | cnn_alerts.csv -> dossiers d'episode + POLICY_FLAGS |
| `prompts_cnn.py` | system prompt, few-shot, schema JSON |
| `llm_client_cnn.py` | client Groq : JSON mode, retry, cache, fail-open |
| `triage_cnn.py` | orchestrateur + garde-fous deterministes |
| `evaluate_triage_cnn.py` | reduction du bruit **vs** retention du rappel |

## Installation

```bash
pip install -r requirements_llm_cnn.txt
echo "GROQ_API_KEY=gsk_..." >> .env
python llm_client_cnn.py --models        # verifier les modeles actifs
```

## Execution

```bash
python train_eval_cnn.py                 # couche 1 (inchangee)
python inference_cnn.py                  # -> cnn_alerts.csv, cnn_alerts_episodes.csv
python triage_cnn.py --dry-run           # prompts + RAG, 0 appel LLM, 0 cout
python triage_cnn.py --limit 5           # essai reel sur 5 episodes
python triage_cnn.py                     # 46 episodes -> cnn_triage.jsonl
python evaluate_triage_cnn.py --gt groundtruth.jsonl
```

## Les trois decisions defendables

1. **Granularite = episode, pas evenement.** 46 appels au lieu de 234, et
   surtout : la malveillance est une propriete de la SEQUENCE. `chmod` seul est
   banal ; `chmod +x .update` -> `crontab` est une kill chain.
2. **RAG hybride, pas vectoriel pur.** Sur 13 chunks, `cups-browsed` (FP) et
   `crontab` (TP) sont voisins dans l'espace semantique. Un match exact sur
   `process_name` les separe ; le cosinus non.
3. **Le LLM propose, la politique dispose.** `POLICY_FLAGS` interdit le verdict
   `false_positive` sur les primitives sensibles (useradd, auditctl, rafale
   d'echecs, binaire cache). Garde-fous deterministes verifiables ligne a ligne :
   le systeme reste auditable meme si le modele derape.

## Metrique

Une couche de triage se juge sur **deux** chiffres, jamais un seul :
reduction du bruit **ET** retention du rappel. Reduire 90 % du bruit en perdant
une attaque sur quatre est un echec. Le seul resultat publiable :
bruit fortement reduit, rappel 4/4 intact.
