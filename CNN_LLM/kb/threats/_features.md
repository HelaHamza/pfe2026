---
id: ref-features
kind: reference
log_source: auth, syslog, auditd
processes:
users:
event_types:
mitre:
severity_hint: info
---
# Semantique des features du CNN (a lire avant toute interpretation)

Le score `mse` est un score de RARETE STATISTIQUE non supervise, pas un score de
malveillance. `mse > threshold` signifie "mal reconstruit par rapport au profil
appris", donc RARE. Rare != malveillant. La couche presente est justement celle
qui tranche rare-benin vs rare-malveillant.

Chaque valeur de `top_features` est un z-score de residu, plafonne a 50.

* `is_fail` (auth) : echec d'authentification. Canal ATOMIQUE, tres discriminant
  pour le brute-force.
* `user_rarity` : rarete de l'utilisateur. Sature pour tout compte vu 1 fois,
  y compris les COMPTES DE SERVICE legitimes (nobody, cups-browsed).
* `proc_rarity` / `exe_path_rarity` : rarete du processus / du chemin du binaire.
  Suivent une loi `50 - 2*ln(F)` avec F = frequence -> tout binaire vu pour la
  PREMIERE fois sature, benin ou non. FAIBLE pouvoir discriminant a lui seul.
* `parent_child_rarity` : rarete du couple parent->enfant. Meme plateau.
* `syscall_rarity` : rarete de l'appel systeme.
* `inter_arrival_log` : log du delai depuis l'evenement precedent. Un z eleve
  apres une nuit / une veille est un artefact de VEILLE, pas une activite
  nocturne. A ne pas surinterpreter.
* `cmd_entropy` + `cmd_length_log` : entropie et longueur de la commande.
  Seule leur CONJONCTION suggere de l'obfuscation.
* `msg_length_log` : longueur du message brut.
* `ip_is_external` : residu, pas un booleen. Un z eleve = "IP mal reconstruite",
  PAS "IP externe". Toujours verifier `source_ip` directement.
* `event_type_seq` : surprise de la tete sequence (-log p du token). Eleve =
  enchainement d'evenements inedit. Souvent domine par le simple bruit desktop.

## Regle d'or
Un episode dont les features dominantes sont UNIQUEMENT des features de rarete
d'identite (proc_rarity, exe_path_rarity, parent_child_rarity, user_rarity) et
dont les acteurs sont des services systeme connus est un candidat FORT au faux
positif. Un episode ou `is_fail`, une sequence useradd/userdel, un binaire cache
ou une chaine chmod->crontab apparaissent est un candidat FORT au vrai positif.
