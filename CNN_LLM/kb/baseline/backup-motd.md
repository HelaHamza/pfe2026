---
id: baseline-backup-motd
kind: baseline
log_source: auditd
processes: (ade-motd), (ease-gtk), 00-header, 10-help-text, 50-motd-news, update-motd, stat, expr, date, cat, uname, seq
users: root
event_types: executed, connected-to, opened-file
mitre:
severity_hint: info
---
# update-motd et scripts de banniere de connexion

Les scripts `/etc/update-motd.d/*` (00-header, 10-help-text, 50-motd-news,
90-updates-available) s'executent a chaque connexion SSH/console. auditd tronque
leurs noms a 15 caracteres, ce qui produit des `process_name` etranges entre
parentheses : `(ade-motd)`, `(ease-gtk)`, `(b-backup)`, `(ogrotate)`.

## Point de vigilance methodologique
Un nom entre parentheses en auditd signifie que le processus a ete observe
APRES un execve mais avant la mise a jour du comm, ou qu'il s'agit d'un nom
tronque. Ce n'est PAS un indicateur de compromission en soi ; il ne faut pas
conclure "nom obfusque" a partir de la seule troncature.

## Ce qui invaliderait la conclusion benigne
* Un script motd modifie recemment (les motd sont un vecteur de persistance
  connu : T1546 / execution a chaque login).
* `50-motd-news` contactant un domaine autre que motd.ubuntu.com.
