"""
mitre_names_cnn.py  --  ajoute le 17/07/2026
=============================================
Table de correspondance technique MITRE -> (tactique, nom).

POURQUOI CE MODULE EXISTE
-------------------------
La v1 demandait au LLM de produire lui-meme technique_id + tactic + name, et
_validate() ne verifiait QUE l'id : tactic et name etaient donc produits de
memoire par le modele et acceptes sans controle. Un T1053.003 etiquete
"Defense Evasion" passait sans un mot.

La v2 corrige : le LLM ne renvoie que l'ID, le systeme remplit le reste. Mais
le run du 17/07/2026 a revele l'effet de bord :

    [rag] 20 technique(s) sans tactique/nom dans la KB : ['T1027',
          'T1053.003', 'T1059.004', 'T1068', 'T1070.002']...

Le front-matter de la KB ne stocke que les identifiants. Resultat : tactic et
name sortaient VIDES -- honnete, mais le dashboard React affiche des cases
blanches, et un mapping ATT&CK sans nom de tactique n'est pas exploitable par
un analyste.

TROIS SOLUTIONS POSSIBLES, ET POURQUOI CELLE-CI
-----------------------------------------------
  1. Laisser le LLM deviner       -> retour au bug v1 (hallucination acceptee)
  2. Annoter les 13 fichiers KB   -> le plus PROPRE, mais 20 techniques a
                                     saisir a la main a quelques jours de la
                                     soutenance, avec un risque de faute de
                                     frappe silencieuse
  3. Table de repli versionnee    -> ce module

La 3 n'est pas un contournement : c'est la meme discipline que ALLOWED_MITRE.
La table est FERMEE, VERSIONNEE, et RELECTURABLE par le jury -- elle n'est pas
generee par un modele. La KB reste prioritaire : si un chunk fournit
'T1053.003|Persistence|Scheduled Task/Job: Cron', c'est ce qui gagne. Ce
module ne sert qu'aux techniques que la KB n'annote pas.

Migration recommandee APRES la soutenance : porter ces valeurs dans le
front-matter des chunks et supprimer ce module. La KB doit rester la source
unique.

Source : MITRE ATT&CK Enterprise. Les techniques listees sont celles
pertinentes pour un HIDS Linux. Une technique absente d'ici ET de la KB sort
avec tactic/name vides -- ce qui est le comportement correct : on ne devine
pas.
"""
from __future__ import annotations

# technique_id -> (tactique, nom)
MITRE_TABLE: dict[str, tuple[str, str]] = {
    # --- Reconnaissance / Discovery -----------------------------------------
    "T1082": ("Discovery", "System Information Discovery"),
    "T1083": ("Discovery", "File and Directory Discovery"),
    "T1087": ("Discovery", "Account Discovery"),
    "T1087.001": ("Discovery", "Account Discovery: Local Account"),
    "T1057": ("Discovery", "Process Discovery"),
    "T1018": ("Discovery", "Remote System Discovery"),
    "T1046": ("Discovery", "Network Service Discovery"),
    "T1033": ("Discovery", "System Owner/User Discovery"),
    "T1049": ("Discovery", "System Network Connections Discovery"),
    "T1016": ("Discovery", "System Network Configuration Discovery"),

    # --- Initial Access / Credential Access ---------------------------------
    "T1110": ("Credential Access", "Brute Force"),
    "T1110.001": ("Credential Access", "Brute Force: Password Guessing"),
    "T1110.003": ("Credential Access", "Brute Force: Password Spraying"),
    "T1110.004": ("Credential Access", "Brute Force: Credential Stuffing"),
    "T1078": ("Defense Evasion", "Valid Accounts"),
    "T1078.003": ("Defense Evasion", "Valid Accounts: Local Accounts"),
    "T1003": ("Credential Access", "OS Credential Dumping"),
    "T1003.008": ("Credential Access",
                  "OS Credential Dumping: /etc/passwd and /etc/shadow"),
    "T1552": ("Credential Access", "Unsecured Credentials"),
    "T1552.001": ("Credential Access", "Unsecured Credentials: Credentials In Files"),
    "T1021": ("Lateral Movement", "Remote Services"),
    "T1021.004": ("Lateral Movement", "Remote Services: SSH"),

    # --- Execution -----------------------------------------------------------
    "T1059": ("Execution", "Command and Scripting Interpreter"),
    "T1059.004": ("Execution", "Command and Scripting Interpreter: Unix Shell"),
    "T1059.006": ("Execution", "Command and Scripting Interpreter: Python"),
    "T1204": ("Execution", "User Execution"),
    "T1204.002": ("Execution", "User Execution: Malicious File"),
    "T1569": ("Execution", "System Services"),
    "T1569.002": ("Execution", "System Services: Service Execution"),

    # --- Persistence ---------------------------------------------------------
    "T1053": ("Persistence", "Scheduled Task/Job"),
    "T1053.003": ("Persistence", "Scheduled Task/Job: Cron"),
    "T1053.006": ("Persistence", "Scheduled Task/Job: Systemd Timers"),
    "T1136": ("Persistence", "Create Account"),
    "T1136.001": ("Persistence", "Create Account: Local Account"),
    "T1098": ("Persistence", "Account Manipulation"),
    "T1098.004": ("Persistence", "Account Manipulation: SSH Authorized Keys"),
    "T1543": ("Persistence", "Create or Modify System Process"),
    "T1543.002": ("Persistence", "Create or Modify System Process: Systemd Service"),
    "T1546": ("Persistence", "Event Triggered Execution"),
    "T1546.004": ("Persistence", "Event Triggered Execution: Unix Shell Configuration Modification"),
    "T1547": ("Persistence", "Boot or Logon Autostart Execution"),
    "T1505": ("Persistence", "Server Software Component"),
    "T1505.003": ("Persistence", "Server Software Component: Web Shell"),

    # --- Privilege Escalation ------------------------------------------------
    "T1068": ("Privilege Escalation", "Exploitation for Privilege Escalation"),
    "T1548": ("Privilege Escalation", "Abuse Elevation Control Mechanism"),
    "T1548.001": ("Privilege Escalation",
                  "Abuse Elevation Control Mechanism: Setuid and Setgid"),
    "T1548.003": ("Privilege Escalation",
                  "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"),
    "T1611": ("Privilege Escalation", "Escape to Host"),

    # --- Defense Evasion -----------------------------------------------------
    "T1027": ("Defense Evasion", "Obfuscated Files or Information"),
    "T1027.002": ("Defense Evasion", "Obfuscated Files or Information: Software Packing"),
    "T1036": ("Defense Evasion", "Masquerading"),
    "T1036.005": ("Defense Evasion", "Masquerading: Match Legitimate Name or Location"),
    "T1036.004": ("Defense Evasion", "Masquerading: Masquerade Task or Service"),
    "T1070": ("Defense Evasion", "Indicator Removal"),
    "T1070.002": ("Defense Evasion", "Indicator Removal: Clear Linux or Mac System Logs"),
    "T1070.003": ("Defense Evasion", "Indicator Removal: Clear Command History"),
    "T1070.004": ("Defense Evasion", "Indicator Removal: File Deletion"),
    "T1070.006": ("Defense Evasion", "Indicator Removal: Timestomp"),
    "T1222": ("Defense Evasion", "File and Directory Permissions Modification"),
    "T1222.002": ("Defense Evasion",
                  "File and Directory Permissions Modification: Linux and Mac"),
    "T1564": ("Defense Evasion", "Hide Artifacts"),
    "T1564.001": ("Defense Evasion", "Hide Artifacts: Hidden Files and Directories"),
    "T1562": ("Defense Evasion", "Impair Defenses"),
    "T1562.001": ("Defense Evasion", "Impair Defenses: Disable or Modify Tools"),
    "T1562.006": ("Defense Evasion", "Impair Defenses: Indicator Blocking"),
    "T1014": ("Defense Evasion", "Rootkit"),
    "T1620": ("Defense Evasion", "Reflective Code Loading"),

    # --- Command and Control / Exfiltration ----------------------------------
    "T1071": ("Command and Control", "Application Layer Protocol"),
    "T1071.001": ("Command and Control", "Application Layer Protocol: Web Protocols"),
    "T1105": ("Command and Control", "Ingress Tool Transfer"),
    "T1571": ("Command and Control", "Non-Standard Port"),
    "T1573": ("Command and Control", "Encrypted Channel"),
    "T1041": ("Exfiltration", "Exfiltration Over C2 Channel"),
    "T1048": ("Exfiltration", "Exfiltration Over Alternative Protocol"),

    # --- Impact --------------------------------------------------------------
    "T1486": ("Impact", "Data Encrypted for Impact"),
    "T1489": ("Impact", "Service Stop"),
    "T1496": ("Impact", "Resource Hijacking"),
    "T1529": ("Impact", "System Shutdown/Reboot"),

    # --- Collection ----------------------------------------------------------
    "T1005": ("Collection", "Data from Local System"),
    "T1074": ("Collection", "Data Staged"),
    "T1074.001": ("Collection", "Data Staged: Local Data Staging"),
}


def lookup(technique_id: str) -> tuple[str, str]:
    """(tactique, nom) ou ('', '') si inconnue.

    Renvoyer du vide est le comportement CORRECT pour une technique inconnue :
    inventer un nom plausible serait exactement le bug qu'on corrige.
    """
    return MITRE_TABLE.get(technique_id.strip().upper(), ("", ""))


def coverage(ids) -> tuple[list[str], list[str]]:
    """(connues, inconnues) -- a afficher au demarrage pour que les trous
    soient visibles avant la soutenance, pas pendant."""
    connues, inconnues = [], []
    for t in ids:
        (connues if t.strip().upper() in MITRE_TABLE else inconnues).append(t)
    return sorted(connues), sorted(inconnues)


if __name__ == "__main__":
    print(f"{len(MITRE_TABLE)} techniques dans la table de repli\n")
    tactiques: dict[str, int] = {}
    for tac, _ in MITRE_TABLE.values():
        tactiques[tac] = tactiques.get(tac, 0) + 1
    for tac, n in sorted(tactiques.items(), key=lambda x: -x[1]):
        print(f"  {n:3d}  {tac}")