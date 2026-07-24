---
id: baseline-desktop-session
kind: baseline
log_source: auth, syslog, auditd
processes: gdm-password], polkitd, pkexec, gnome-keyring-daemon, dbus-daemon, charon, gsd-rfkill, evolution-calen, whoopsie, at-spi-bus-laun, pool-gsd-screen, pool-pavucontro, Chrome_ChildIOT, gnome-text-edit, libuv-worker, systemd, systemd-modules-load, kernel, rsyslogd, CRON, fstrim, hdparm, sysstat.sleep, snapd-apparmor
users: hala-hamza, root, gdm
event_types: session_open, session_close, executed, connected-to, bound-socket, desktop, init, kernel, other
mitre:
severity_hint: info
---
# Session de bureau GNOME et maintenance systeme (poste ASUS-X415JA)

L'hote est un POSTE DE TRAVAIL Ubuntu, pas un serveur. Consequence directe :
une session graphique produit en permanence des processus a occurrence unique.

Familles benignes recurrentes :
* Ouverture de session : gdm-password, polkitd, gnome-keyring-daemon, dbus-daemon.
* `pkexec` par l'utilisateur `hala-hamza` = elevation LEGITIME via l'agent
  d'authentification GNOME (une boite de dialogue mot de passe a ete affichee).
* Threads nommes : pool-gsd-screen, pool-pavucontro, libuv-worker,
  Chrome_ChildIOT, at-spi-bus-laun -> ce sont des noms de THREAD tronques a
  15 caracteres par le noyau, pas des binaires distincts.
* Maintenance : fstrim (hebdo), hdparm (spindown), sysstat.sleep (cron 10 min),
  systemd-modules-load, whoopsie (rapport de crash Ubuntu).
* `charon` = demon IPsec strongSwan (VPN).

## Pourquoi le CNN le note anormal (attendu)
* `inter_arrival_log` sature apres une periode d'inactivite (nuit, veille) :
  le premier evenement au reveil a un delai inter-arrivee enorme -> z eleve.
  C'est un artefact de VEILLE, pas une activite nocturne suspecte.
* `proc_rarity` sature au PREMIER lancement d'un outil desktop dans la fenetre.
* `parent_child_rarity` sature pour tout couple parent->enfant vu 1 fois.

## Ce qui invaliderait la conclusion benigne
* `pkexec` SANS session graphique active ou avec des arguments etranges
  -> CVE-2021-4034 (PwnKit), T1548.001.
* Un thread au nom systeme s'executant depuis /tmp ou un chemin cache.
* Une session ouverte pour un utilisateur qui n'existait pas la veille.
