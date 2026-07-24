---
id: baseline-logrotate
kind: baseline
log_source: auditd, syslog
processes: logrotate, savelog, gzip, dpkg-db-backup, rsyslog-rotate, invoke-rc.d, runlevel, cp, mv, rm, date, basename, dirname, sh, systemctl, (ogrotate), (b-backup)
users: root
event_types: executed, connected-to, opened-file, changed-file-permissions-of, changed-file-ownership-of
mitre:
severity_hint: info
---
# Rotation quotidienne des journaux (cron.daily)

Sur Ubuntu, `/etc/cron.daily/logrotate` s'execute une fois par jour, typiquement
entre 23h00 et 00h30 selon `systemd-cron` / anacron. En quelques secondes il
genere une RAFALE de dizaines d'evenements auditd sous UID 0 :

  logrotate -> savelog / gzip / cp / mv / rm / date / basename / dirname
  dpkg-db-backup -> tar/gzip vers /var/backups
  rsyslog-rotate -> systemctl kill -s HUP rsyslog

## Pourquoi le CNN le note anormal (attendu)
* `parent_child_rarity` et `proc_rarity` explosent : ces couples parent->enfant
  n'apparaissent qu'UNE fois par 24h, donc quasi absents de la fenetre
  d'entrainement -> rarete statistique maximale.
* `exe_path_rarity` eleve pour /usr/bin/savelog, /usr/sbin/logrotate.
* La densite (dizaines d'evenements en <6 s) sature la tete sequence.

C'est une RARETE BENIGNE, pas une anomalie de securite.

## Signature de confirmation
* Fenetre : ~23:00:00 +/- quelques minutes, duree < 30 s.
* `user_name` = root, uid 0, parent = cron / CRON / run-parts.
* Binaires TOUS dans /usr/bin, /usr/sbin, /bin (jamais /tmp, /dev/shm, ~/).
* Cibles : /var/log/*, /var/backups/*.

## Ce qui invaliderait la conclusion benigne
* Un enfant hors chemin systeme (/tmp/x, ./script.sh, chemin cache `.`).
* Une cible hors /var/log ni /var/backups (ex. /etc/shadow, /root/.ssh).
* Un `rm` sur /var/log/auth.log ou /var/log/audit/* SANS rotation associee
  -> T1070.002 (Indicator Removal: Clear Linux Logs).
* Une execution hors de la fenetre horaire cron.daily habituelle.
