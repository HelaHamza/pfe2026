---
id: threat-obfuscation-execution
kind: threat
log_source: auditd
processes: bash, sh, dash, python3, perl, base64, openssl, xxd, eval
users:
event_types: executed
mitre: T1027, T1059.004, T1140
severity_hint: high
---
# Execution obfusquee / encodee (T1027, T1059.004, T1140)

## Signature observable
* `base64 -d | bash`, `echo <blob> | base64 -d | sh`, `eval $(...)`.
* Ligne de commande longue et a forte entropie -> `cmd_entropy` +
  `cmd_length_log` eleves SIMULTANEMENT. C'est la CONJONCTION qui compte :
  une commande longue mais a faible entropie (chemin de fichier) est banale.
* `process_name` en hexadecimal (ex. `47616D6570616420706F6C6C696E67`) :
  ATTENTION, ici il s'agit du champ auditd `proctitle` encode en hex par le
  demon lui-meme quand la ligne de commande contient des espaces. Le decodage
  donne "Gamepad polling" = thread SDL/navigateur -> BENIN. Ne pas confondre
  encodage de TRANSPORT auditd et obfuscation d'ATTAQUANT.

## Regle de discrimination
Obfuscation reelle = le CONTENU decode est du code executable.
Artefact auditd = le contenu decode est un nom de thread ou une commande banale.
Toujours decoder avant de conclure.

## Recommandations
1. Decoder le proctitle : `python3 -c "print(bytes.fromhex('...').decode())"`.
2. Si code reel : reconstruire la commande complete via `ausearch -m EXECVE`.
3. Rechercher le point d'entree (telechargement, piece jointe, webshell).
