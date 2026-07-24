---
id: baseline-snapd-apt
kind: baseline
log_source: auditd, syslog
processes: snapd, snapctl, snapd-apparmor, post-refresh, apparmor_parser, xdelta3, mkdir, rm, dpkg, apt, unattended-upgrade, check-new-release-gtk, check-new-relea
users: root
event_types: executed, connected-to, opened-file, violated-apparmor-policy, changed-configuration
mitre:
severity_hint: info
---
# Mises a jour snapd / APT / AppArmor

Le refresh automatique des snaps (4x/jour par defaut) et `unattended-upgrades`
generent des sequences root atypiques :

  snapd -> xdelta3 (delta binaire du snap)
  snapd -> apparmor_parser (recompilation des profils)  -> violated-apparmor-policy
  snapd -> post-refresh -> snapctl -> mkdir / rm
  snapd -> connected-to api.snapcraft.io (HTTPS sortant)

## Pourquoi le CNN le note anormal (attendu)
* `exe_path_rarity` sature pour xdelta3, apparmor_parser, post-refresh : ces
  binaires ne tournent que lors d'un refresh -> premiere occurrence = rarete max
  (cf. plateau `50 - 2*ln(F)` du scoring d'identite).
* `snapd -> connected-to` recurrent toutes les ~30 min (heartbeat).

## Signature de confirmation
* Parent = snapd ou systemd, uid 0.
* Binaires dans /usr/lib/snapd/, /usr/bin/, /snap/.
* `violated-apparmor-policy` emis PAR apparmor_parser lui-meme = recompilation
  de profil, pas une violation d'un processus tiers.

## Ce qui invaliderait la conclusion benigne
* Un snap installe depuis un chemin local inhabituel (`snap install --dangerous`).
* apparmor_parser retirant un profil (`-R`) sur un service de securite.
* `connected-to` vers un domaine non-Canonical.
