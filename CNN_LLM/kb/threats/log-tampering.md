---
id: threat-log-tampering
kind: threat
log_source: auditd, syslog
processes: auditctl, rm, shred, truncate, systemctl, service, journalctl, logrotate, chattr
users:
event_types: changed-audit-configuration, executed, opened-file, changed-file-permissions-of
mitre: T1070.002, T1562.001, T1562.012
severity_hint: high
---
# Alteration des journaux et de l'audit (T1070.002, T1562.001)

## Signature observable
* `changed-audit-configuration` : modification des regles auditd. Legitime si
  elle provient d'un deploiement trace (Ansible, apt sur auditd) ou du demarrage
  du service ; SUSPECTE si elle vient d'un shell interactif utilisateur.
* `auditctl -e 0` (audit desactive), `auditctl -D` (regles purgees).
* `systemctl stop auditd|rsyslog|auditbeat` -> T1562.001 Impair Defenses.
* `rm` / `shred` / `truncate -s 0` sur /var/log/auth.log, /var/log/syslog,
  /var/log/audit/audit.log HORS rotation logrotate.
* `chattr -i` puis suppression = levee d'immutabilite.

## Discrimination baseline vs attaque
Sur ce poste, `changed-audit-configuration` apparait aux redemarrages du demon
auditd et lors des mises a jour du paquet -> a correler avec l'uid, le parent
et la presence simultanee d'une mise a jour APT/snapd. Si l'auid est un
utilisateur interactif et qu'aucune mise a jour n'est en cours -> escalader.

## Recommandations
1. `auditctl -s` et `auditctl -l` : comparer aux regles de reference.
2. Verifier l'integrite des journaux (trous temporels, taille anormale).
3. Confirmer que l'expedition distante (Filebeat/Auditbeat -> ELK) n'a pas ete
   coupee : la copie ELK est la source de verite si l'hote est compromis.
4. Correler avec un changement planifie ; sinon, traiter en incident.
