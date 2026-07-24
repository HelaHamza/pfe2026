---
id: baseline-cups-browsed
kind: baseline
log_source: auditd
processes: cups-browsed, cupsd
users: cups-browsed, root, lp
event_types: executed, bound-socket, opened-file, connected-to, violated-apparmor-policy
mitre:
severity_hint: info
---
# Service d'impression CUPS (cups-browsed / cupsd)

`cups-browsed` decouvre les imprimantes reseau (protocole DNS-SD/mDNS). Au
demarrage du service il ouvre une rafale de sockets vers 631/tcp et le reseau
local -> dizaines d'evenements `connected-to` en < 1 s.

## Pourquoi le CNN le note anormal (attendu)
* Il s'execute sous le compte de service dedie `cups-browsed`, qui n'apparait
  presque jamais ailleurs -> `user_rarity` sature (z ~ 50).
* La rafale de `connected-to` est dense et atypique.
* `cupsd` declenche regulierement `violated-apparmor-policy` : le profil
  AppArmor d'Ubuntu est plus strict que les besoins reels de CUPS. C'est un
  bruit CONNU d'Ubuntu, pas un contournement.

## Signature de confirmation
* `process_name` = cups-browsed, `user_name` = cups-browsed (compte de service).
* exe = /usr/sbin/cups-browsed, parent = systemd (PID 1).
* Rafale correlee au demarrage du service ou a un evenement reseau.

## Ce qui invaliderait la conclusion benigne
* Le compte `cups-browsed` executant un shell (bash, sh, dash) -> abus de
  compte de service.
* `connected-to` vers une IP publique externe (exfiltration).
* Un binaire nomme cups-browsed hors de /usr/sbin -> masquerading T1036.005.
