---
id: threat-privilege-escalation
kind: threat
log_source: auth, auditd
processes: sudo, su, pkexec, doas, chmod, chown, setcap, dbus-send
users: root
event_types: executed, changed-file-permissions-of, changed-file-ownership-of, session_open
mitre: T1548.001, T1548.003, T1068, T1222.002
severity_hint: high
---
# Escalade de privileges (T1548.003, T1548.001, T1222.002)

## Signature observable
* `sudo` / `su` par un utilisateur non habituel, ou echecs `sudo` repetes
  (`user NOT in sudoers`) -> tentative d'escalade.
* `pkexec` sans session graphique -> exploitation type PwnKit (CVE-2021-4034).
* `chmod 4755` / `chmod u+s` sur un binaire -> pose d'un SUID backdoor
  (T1548.001 Setuid and Setgid).
* `chmod 777` sur /etc/*, `chown root:root` sur un binaire depose par un
  utilisateur -> T1222.002 Linux File Permissions Modification.
* Ecriture dans /etc/sudoers.d/ ou /etc/sudoers.

## Discrimination baseline vs attaque
Sur un poste de bureau, `pkexec` par l'utilisateur du bureau PENDANT une session
graphique active est la voie NORMALE d'elevation (installation logicielle,
parametres systeme). Le signal est le CONTEXTE : session presente ? heure ?
processus parent = agent d'authentification GNOME ?

## Recommandations
1. `ausearch -m EXECVE -ua <auid>` pour reconstituer la session complete.
2. Rechercher les SUID inattendus : `find / -perm -4000 -newer /etc/hostname`.
3. Verifier /etc/sudoers.d/ et l'appartenance aux groupes sudo/adm.
