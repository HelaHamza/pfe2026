---
id: baseline-dnsmasq-network
kind: baseline
log_source: auditd, syslog
processes: dnsmasq, dnsmasq-dhcp, NetworkManager, nm-dispatcher, wpa_supplicant, systemd-resolved
users: nobody, root, systemd-resolve
event_types: connected-to, bound-socket, executed
mitre:
severity_hint: info
---
# Resolution DNS locale (dnsmasq sous 'nobody')

`dnsmasq` est lance par NetworkManager pour le DNS/DHCP local. Par conception,
il abandonne ses privileges et tourne sous l'utilisateur **nobody** apres avoir
bind le port 53. C'est un durcissement standard, pas une anomalie.

## Pourquoi le CNN le note anormal (attendu)
* `user_rarity` sature (z = 50) : `nobody` n'apparait presque QUE la.
  Le modele voit un utilisateur quasi-unique -> rarete maximale.
* `nm-dispatcher` ne s'execute qu'aux changements d'etat reseau (wifi up/down)
  -> `proc_rarity` sature ponctuellement.

## Signature de confirmation
* exe = /usr/sbin/dnsmasq, parent = NetworkManager.
* `connected-to` vers la passerelle locale / resolveur amont.
* uid = nobody UNIQUEMENT pour dnsmasq.

## Ce qui invaliderait la conclusion benigne
* `nobody` executant autre chose que dnsmasq (shell, curl, wget, nc)
  -> compromission d'un service, T1078.003.
* dnsmasq faisant `executed` d'un enfant -> execution de commande via DNS.
