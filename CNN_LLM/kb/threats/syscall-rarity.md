---
id: threat-syscall-rarity
kind: threat
log_source: auditd
processes: strace, gdb, ptrace, setcap, insmod, modprobe, touch
event_types: syscall
mitre: T1055|Defense Evasion|Process Injection, T1548|Privilege Escalation|Abuse Elevation Control Mechanism, T1547.006|Persistence|Boot or Logon Autostart Execution: Kernel Modules and Extensions, T1070.006|Defense Evasion|Indicator Removal: Timestomp
severity_hint: high
---
Syscalls rarement observes sur un poste de travail, souvent lies a des actions
offensives. Le CNN les remonte via la feature syscall_rarity.

Motifs et lecture :
- ptrace (souvent via strace, gdb) : debogage LEGITIME, mais aussi injection de
  code et lecture memoire d'un autre processus (T1055). Ne pas clore sans savoir
  quel processus est cible.
- capset / setcap : attribution de capabilities (T1548) -> elevation possible.
- finit_module / insmod / modprobe : chargement de module noyau (T1547.006) ->
  rootkit possible si le module est inconnu.
- utimensat (souvent via touch -t vers une date passee) : modification
  d'horodatage de fichier (T1070.006, timestomp) -> anti-forensique. Signal
  FAIBLE, difficile a distinguer d'un usage benin de touch.

VERDICT ATTENDU : un syscall rare et sensible n'est JAMAIS un false_positive par
defaut. Si le contexte ne permet pas de confirmer une intention malveillante,
repondre "uncertain" (escalade). Ne confirmer "true_positive" que si un motif
clair accompagne le syscall (cible du ptrace identifiee, module inconnu charge,
chaine d'actions coordonnee).