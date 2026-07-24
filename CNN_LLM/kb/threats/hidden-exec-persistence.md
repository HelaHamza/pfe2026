---
id: threat-hidden-exec-persistence
kind: threat
log_source: auditd
processes: crontab, at, systemctl, .rk_beacon, .update, curl, wget, nc, ncat, socat, chmod, base64, python3, perl, bash, sh
users:
event_types: executed, opened-file, changed-file-permissions-of, connected-to
mitre: T1053.003, T1543.002, T1547.006, T1059.004, T1564.001, T1105
severity_hint: critical
---
# Execution cachee et persistance (T1053.003, T1564.001, T1059.004)

## Signature observable : binaire a nom cache
Un `process_name` commencant par un POINT (`.rk_beacon`, `.update`, `.x`) est
un fichier CACHE sous Linux (T1564.001 Hide Artifacts: Hidden Files). Un binaire
legitime ne se cache pas. Combinaison typique d'un implant :

  bash -> chmod +x .update -> ./.update (execution)
  seq / while -> .rk_beacon (boucle de beaconing, executions periodiques)
  crontab -e / crontab -l -> persistance

Repetitions du MEME binaire cache a intervalle regulier (ex. 3 executions a
~300 ms) = boucle de BEACONING, signature classique de C2.

## Signature observable : persistance par cron
* `crontab` execute par un utilisateur NON-root en dehors d'une tache
  d'administration tracee -> T1053.003 Scheduled Task/Job: Cron.
* Ecriture dans /var/spool/cron/crontabs/, /etc/cron.d/, /etc/cron.daily/.
* Enchainement `chmod +x` -> `crontab` dans la MEME minute = installation de
  persistance, pas de la maintenance.

## Signature observable : chaine complete
  cat/chmod -> binaire cache -> crontab -> connected-to
= depot d'outil (T1105) + execution (T1059.004) + persistance (T1053.003)
+ C2. C'est une KILL CHAIN, la severite est critical meme si chaque etape prise
isolement semble anodine.

## Traduction en features CNN
* `proc_rarity` et `exe_path_rarity` saturent (binaire jamais vu).
* `parent_child_rarity` sature (couple bash->.update inedit).
* ATTENTION : ces memes features saturent aussi pour tout binaire benin lance
  pour la premiere fois (cf. plateau d'identite). Le score seul NE distingue
  PAS. La discrimination vient du CHEMIN, du NOM, de la SEQUENCE et du
  DECLENCHEUR -> c'est exactement le role de cette couche.

## Recommandations
1. Localiser et figer le binaire : `find / -name '.rk_beacon' -ls`, hash SHA256.
2. `crontab -l -u <user>`, inspecter /etc/cron.*, /var/spool/cron/crontabs/.
3. Lister les connexions sortantes : `ss -tunp`, correler avec `connected-to`.
4. Isoler l'hote du reseau AVANT nettoyage (preserver la memoire).
5. Chercher les autres mecanismes de persistance : systemd user units,
   ~/.bashrc, ~/.profile, /etc/update-motd.d/, cles SSH authorized_keys.
