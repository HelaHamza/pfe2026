---
id: threat-account-manipulation
kind: threat
log_source: auth, auditd
processes: useradd, userdel, usermod, groupadd, gpasswd, passwd, chpasswd, adduser
users:
event_types: executed, ssh_login, changed-password
mitre: T1136.001, T1098, T1078.003
severity_hint: high
---
# Creation / suppression de compte local (T1136.001, T1098)

## Signature observable
* `useradd` puis, quelques secondes plus tard, `userdel` du MEME compte.
  Ce couple serre est un marqueur FORT : creation d'un compte de secours puis
  effacement des traces, ou test d'un playbook offensif.
* Compte au nom non conforme a la convention de l'organisation (testintrus,
  backup2, svc-tmp, support1).
* Creation hors fenetre de changement / hors horaires ouvres.
* Correlation avec un evenement d'acces precedent (brute-force, session SSH).

## Traduction en features CNN
* `user_rarity` sature : le compte n'a jamais ete vu -> z max.
* `event_type_seq` eleve : la sequence useradd->userdel est absente du profil.

## Tactique / technique
* Persistence (TA0003) : T1136.001 Create Account: Local Account.
* Persistence / Privilege Escalation : T1098 Account Manipulation si ajout au
  groupe sudo/wheel/adm.

## Facteur aggravant
Un `useradd` suivi de `usermod -aG sudo` ou d'une ecriture dans /etc/sudoers.d/
= escalade de privileges preparee -> severite critical.

## Recommandations
1. Verifier l'existence residuelle du compte : `getent passwd <user>`.
2. Auditer /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers.d/.
3. Identifier l'utilisateur d'origine (auid) et sa session : `ausearch -ua <auid>`.
4. Verifier les cles SSH deposees dans le home du compte cree.
5. Ne JAMAIS clore une creation de compte comme faux positif sans confirmation
   d'un changement planifie trace.
