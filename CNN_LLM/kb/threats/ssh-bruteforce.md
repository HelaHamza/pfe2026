---
id: threat-ssh-bruteforce
kind: threat
log_source: auth
processes: sshd
users: invaliduser, admin, test, oracle, ubuntu, postgres
event_types: ssh_login, ssh, session_failed
mitre: T1110.001, T1110.003
severity_hint: high
---
# Brute-force / password spraying SSH (T1110.001)

## Signature observable dans auth
* Series rapprochees de `sshd` avec `event_type=ssh_login` et `is_fail` actif.
* `user_name` variant a chaque tentative (invaliduser1..N, admin, root, test)
  depuis une MEME `source_ip` -> credential stuffing / enumeration.
* Cadence reguliere : 200-400 ms entre tentatives -> signature AUTOMATISEE.
  Un humain ne tape pas 60 mots de passe en 15 secondes.

## Traduction en features CNN
* `is_fail` = canal atomique, z sature (jusqu'a 50) sur les premieres tentatives.
* `user_rarity` eleve : chaque utilisateur est vu une seule fois.
* `ip_is_external` : residu eleve car l'IP source ne correspond pas au profil
  appris. ATTENTION : un residu eleve signifie "mal reconstruit", pas
  "IP externe". Une attaque simulee depuis 127.0.0.1 peut donc faire saturer
  `ip_is_external` sans que l'IP soit reellement externe.
* Decroissance du score au fil de la rafale = ADAPTATION du modele au motif
  repetitif, PAS une baisse de gravite. Le premier evenement porte le score max.

## Tactique / technique
* Tactique : Credential Access (TA0006).
* Technique : T1110.001 Password Guessing ; T1110.003 Password Spraying si
  1 mot de passe teste sur beaucoup de comptes.

## Escalade critique
Si la rafale d'echecs est SUIVIE d'un `Accepted password` / `session opened`
pour un des comptes testes -> brute-force REUSSI, severite critical, passer
en reponse a incident immediate.

## Recommandations
1. Isoler / bloquer la source_ip (fail2ban, nftables).
2. Verifier si un `Accepted` suit la rafale dans les 60 s.
3. `PasswordAuthentication no` + auth par cle ; MaxAuthTries 3.
4. Verifier /var/log/auth.log en amont pour la duree reelle de la campagne.
