"""
=============================================================================
KNOWLEDGE BASE — Base de connaissances locale pour le RAG IDS
=============================================================================

Contient les descriptions des attaques détectées par le MoE-AE.
Chaque entrée mappe des flags binaires (features Logstash) vers :
    - une description de l'attaque
    - les techniques MITRE ATT&CK correspondantes
    - des actions de remédiation concrètes

UTILISATION :
    from knowledge_base import retrieve_knowledge_context
    ctx = retrieve_knowledge_context(anomaly_dict)
    # ctx est une string prête à être injectée dans le prompt LLM

=============================================================================
"""

# =============================================================================
# SECTION A — BASE DE CONNAISSANCES
# =============================================================================
# Chaque entrée :
#   id          : identifiant unique
#   title       : nom lisible
#   indicators  : liste de flags — si AU MOINS UN vaut 1 → entrée pertinente
#   description : contexte de l'attaque pour le LLM
#   mitre       : technique(s) MITRE ATT&CK
#   severity    : CRITICAL / HIGH / MEDIUM / LOW
#   context     : signaux numériques à surveiller (pour enrichir le prompt)
#   remediation : actions concrètes ordonnées par priorité
# =============================================================================

THREAT_KNOWLEDGE = [
    {
        "id": "auditd_suspicious_activity",
        "title": "Activité auditd suspecte",
        "indicators": [
            "aud_severity",
            "aud_sev_norm",
            "aud_suspicious_combo",
        ],
        "description": (
            "Score de sévérité auditd non nul sans flag d'attaque "
            "spécifique identifié. aud_severity est une somme pondérée "
            "de signaux faibles : entropy élevée, arguments suspects, "
            "syscall inhabituel. Seul, il indique une surveillance "
            "accrue plutôt qu'une attaque confirmée."
        ),
        "mitre": "T1059 — Command and Scripting Interpreter",
        "severity": "LOW",
        "context": [
            "aud_severity  : score de sévérité auditd (>0 = suspect)",
            "aud_sev_norm  : sévérité normalisée 0-1",
            "ae_mse_error  : erreur de reconstruction (anomalie statistique)",
        ],
        "remediation": [
            "Inspecter les logs auditd bruts : ausearch -ts recent",
            "Identifier le processus source : ausearch -p <pid>",
            "Vérifier les appels syscall inhabituels : aureport --syscall",
            "Corréler avec d'autres événements de la même période",
            "Surveiller si l'activité se répète ou s'intensifie",
        ],
    },
    {
        "id": "brute_force_ssh",
        "title": "Brute Force SSH",
        "indicators": [
            "auth_is_brute_force",
            "auth_is_slow_bruteforce",
            "auth_fail_count_5m",
        ],
        "description": (
            "Tentatives répétées de connexion SSH depuis une IP externe. "
            "Le seuil de détection est ≥5 échecs en 5 minutes (brute force rapide) "
            "ou ≥8 échecs en 10 minutes (slow brute force pour contourner fail2ban). "
            "Peut précéder une intrusion réussie — vérifier cross_bruteforce_success."
        ),
        "mitre": "T1110 — Brute Force / T1110.003 — Password Spraying",
        "severity": "HIGH",
        "context": [
            "auth_fail_count_5m   : nombre d'échecs dans les 5 dernières minutes",
            "auth_fail_window_10m : nombre d'échecs dans les 10 dernières minutes",
            "auth_fail_ratio      : ratio échecs / total tentatives",
            "auth_users_tried     : nombre de comptes différents testés",
            "cross_bruteforce_success : 1 si connexion réussie après les échecs",
        ],
        "remediation": [
            "Bloquer immédiatement l'IP source dans le firewall (iptables -A INPUT -s <IP> -j DROP)",
            "Vérifier si une connexion a réussi après les échecs (cross_bruteforce_success=1)",
            "Inspecter les sessions actives : who, last, w",
            "Activer ou vérifier fail2ban : fail2ban-client status sshd",
            "Renforcer l'authentification SSH : désactiver les mots de passe, imposer les clés",
        ],
    },
    {
        "id": "credential_stuffing",
        "title": "Credential Stuffing",
        "indicators": [
            "auth_is_stuffing",
            "auth_is_user_enum",
        ],
        "description": (
            "Test automatisé de credentials volés sur de nombreux comptes différents. "
            "Détecté quand ≥5 utilisateurs différents sont testés depuis la même IP. "
            "L'énumération de comptes (auth_is_user_enum) précède souvent le stuffing. "
            "Indique l'utilisation d'une liste de credentials compromise (type breach)."
        ),
        "mitre": "T1110.004 — Credential Stuffing / T1589 — Gather Victim Identity Information",
        "severity": "HIGH",
        "context": [
            "auth_users_tried     : nombre de comptes différents testés depuis cette IP",
            "unique_users_per_ip  : confirmé par le compteur agrégat Logstash",
            "auth_fail_ratio      : ratio d'échecs (généralement élevé)",
        ],
        "remediation": [
            "Bloquer l'IP source et vérifier si d'autres IPs similaires sont actives",
            "Forcer la réinitialisation des mots de passe des comptes ciblés",
            "Activer MFA sur tous les comptes exposés",
            "Vérifier si des comptes ont été compromis dans des breaches connues (HaveIBeenPwned)",
            "Mettre en place un rate limiting sur les tentatives d'authentification",
        ],
    },
    {
        "id": "privilege_escalation",
        "title": "Élévation de privilèges",
        "indicators": [
            "auth_sudo_to_root",
            "aud_ptrace",
            "aud_suid_abuse",
            "aud_process_injection",
        ],
        "description": (
            "Tentative d'acquisition des droits root par différents vecteurs : "
            "sudo après connexion SSH (cross_ssh_then_sudo), exploitation de binaires SUID, "
            "injection de processus via ptrace, ou manipulation mémoire. "
            "Souvent la deuxième étape après une compromission initiale."
        ),
        "mitre": "T1548 — Abuse Elevation Control Mechanism / T1055 — Process Injection",
        "severity": "CRITICAL",
        "context": [
            "aud_ptrace          : appel système ptrace détecté — injection ou débogage suspect",
            "aud_suid_abuse      : chmod u+s ou permission 4xxx sur un binaire",
            "cross_ssh_then_sudo : SSH réussi puis sudo dans les 10 minutes",
            "aud_sev_norm        : sévérité normalisée auditd (proche de 1.0 = critique)",
        ],
        "remediation": [
            "Identifier le processus source : ps auxf | grep <pid>",
            "Vérifier les binaires SUID modifiés récemment : find / -perm -4000 -mtime -1",
            "Auditer les règles sudoers : cat /etc/sudoers, visudo -c",
            "Vérifier les modules kernel chargés : lsmod | diff - /tmp/lsmod_baseline",
            "Isoler la machine si élévation confirmée",
        ],
    },
    {
        "id": "log_tampering",
        "title": "Falsification ou suppression de logs",
        "indicators": [
            "aud_log_tamper",
            "aud_log_delete",
            "sys_log_tamper",
        ],
        "description": (
            "Suppression ou modification des fichiers de logs système (/var/log/auth.log, "
            "syslog, wtmp, btmp). Indicateur fort de post-exploitation — l'attaquant "
            "efface ses traces après l'intrusion. Souvent précédé d'autres attaques. "
            "La corrélation temporelle avec d'autres événements est cruciale."
        ),
        "mitre": "T1070 — Indicator Removal / T1070.002 — Clear Linux System Logs",
        "severity": "CRITICAL",
        "context": [
            "aud_log_delete  : syscall unlink/truncate sur des fichiers .log",
            "sys_log_tamper  : erreur logrotate ou journal miss détectée",
            "aud_log_tamper  : accès suspect au démon auditd ou journald",
        ],
        "remediation": [
            "Vérifier l'intégrité des logs via le SIEM (comparer avec les copies distantes)",
            "Identifier l'utilisateur/processus : ausearch -k log_tamper",
            "Corréler avec les événements des 30 dernières minutes",
            "Préserver une copie forensique de l'état actuel du système",
            "Initier une réponse à incident formelle — les preuves sont peut-être effacées",
        ],
    },
    {
        "id": "reverse_shell",
        "title": "Reverse Shell / Command & Control",
        "indicators": [
            "aud_reverse_shell",
            "aud_cmd_is_obfuscated",
            "msg_has_base64",
        ],
        "description": (
            "Commande obfusquée ou encodée en base64 ouvrant une connexion sortante "
            "vers un serveur C2 distant. Techniques classiques : bash -i, /dev/tcp, "
            "nc -e, mkfifo. L'obfuscation (entropie > 4.5, base64) indique une tentative "
            "de contournement des signatures de détection."
        ),
        "mitre": "T1059 — Command and Scripting Interpreter / T1027 — Obfuscated Files",
        "severity": "CRITICAL",
        "context": [
            "aud_cmd_entropy      : entropie de la commande (>4.5 = obfusquée)",
            "aud_cmd_length_log   : longueur log de la commande (longue = suspect)",
            "msg_has_base64       : chaîne base64 détectée dans le message",
            "aud_cmd_is_obfuscated: combinaison entropy + patterns détectés",
        ],
        "remediation": [
            "Identifier l'IP de destination : netstat -tupn | grep ESTABLISHED",
            "Tuer le processus immédiatement : kill -9 <pid>",
            "Bloquer la connexion sortante au niveau réseau",
            "Analyser le processus parent pour trouver le vecteur d'entrée",
            "Rechercher la persistance : crontab -l, systemctl list-units, cat ~/.bashrc",
        ],
    },
    {
        "id": "lateral_movement",
        "title": "Mouvement latéral",
        "indicators": [
            "is_lateral_movement",
            "sys_lateral_ssh",
            "cross_ssh_then_sudo",
            "cross_multi_source",
            "unique_hosts_accessed",
        ],
        "description": (
            "Connexions vers plusieurs machines internes dans une fenêtre courte "
            "(≥3 machines en 10 minutes). Après compromission initiale, l'attaquant "
            "pivote vers d'autres systèmes. Le pattern SSH → sudo sur une nouvelle machine "
            "est un indicateur fort. Peut utiliser des clés SSH volées ou implantées."
        ),
        "mitre": "T1021.004 — Remote Services: SSH / T1570 — Lateral Tool Transfer",
        "severity": "HIGH",
        "context": [
            "unique_hosts_accessed : nombre de machines accédées dans les 10 dernières minutes",
            "cross_ssh_then_sudo   : SSH réussi suivi d'un sudo (pivot confirmé)",
            "sys_lateral_ssh       : SSH accepté depuis une IP interne (RFC1918)",
            "cross_multi_source    : événements sur auth + auditd + syslog simultanément",
        ],
        "remediation": [
            "Cartographier toutes les connexions SSH des dernières 24h : grep 'Accepted' /var/log/auth.log",
            "Vérifier les clés SSH autorisées sur chaque machine compromise",
            "Chercher des clés implantées : find / -name authorized_keys -newer /tmp",
            "Révoquer tous les tokens et clés SSH de l'utilisateur compromis",
            "Segmenter le réseau pour contenir la propagation",
        ],
    },
    {
        "id": "data_exfiltration",
        "title": "Exfiltration de données",
        "indicators": [
            "aud_exfiltration",
            "aud_network_scan",
        ],
        "description": (
            "Transfert de données vers une IP externe non autorisée via curl, wget, "
            "scp, rsync ou des protocoles covert (dnscat, dns2tcp). "
            "Souvent précédé d'un scan réseau interne pour identifier les cibles. "
            "Le volume (payload_size_log) et la destination sont les indicateurs clés."
        ),
        "mitre": "T1041 — Exfiltration Over C2 Channel / T1046 — Network Service Discovery",
        "severity": "CRITICAL",
        "context": [
            "payload_size_log  : volume de données transférées (log)",
            "aud_network_scan  : nmap, masscan, nc -z détectés avant l'exfiltration",
            "msg_has_url       : URL externe dans la commande",
            "aud_exfiltration  : curl/wget vers IP externe avec -T ou --data",
        ],
        "remediation": [
            "Identifier l'IP de destination et bloquer immédiatement",
            "Analyser les fichiers accédés avant l'exfiltration : ausearch -sc open",
            "Évaluer le volume et la nature des données potentiellement exfiltrées",
            "Notifier le DPO si données personnelles potentiellement concernées (RGPD)",
            "Préserver les logs réseau pour l'investigation forensique",
        ],
    },
    {
        "id": "cryptominer",
        "title": "Cryptominage malveillant",
        "indicators": [
            "aud_cryptominer",
            "sys_high_cpu_process",
        ],
        "description": (
            "Processus utilisant intensivement le CPU/GPU pour miner des cryptomonnaies "
            "sans autorisation. Détecté via les patterns xmrig, stratum+tcp, cpuminer. "
            "Souvent installé après une intrusion via cron ou un service systemd. "
            "Impact : surcharge CPU, augmentation des coûts d'infrastructure."
        ),
        "mitre": "T1496 — Resource Hijacking / T1053 — Scheduled Task",
        "severity": "MEDIUM",
        "context": [
            "aud_cryptominer      : pattern xmrig/stratum+tcp/ethminer détecté",
            "sys_high_cpu_process : processus avec nice très négatif (priorité maximale)",
            "aud_cron_backdoor    : installation via crontab suspect",
        ],
        "remediation": [
            "Identifier et tuer le processus : ps aux | grep -E 'xmrig|miner|stratum'",
            "Rechercher le vecteur d'installation : crontab -l, systemctl list-units --type=service",
            "Vérifier les connexions réseau actives vers des pools de mining",
            "Auditer les comptes créés récemment : lastlog, cat /etc/passwd | tail",
            "Scanner les binaires modifiés : find /usr /bin /tmp -newer /var/log/dpkg.log",
        ],
    },
    {
        "id": "credential_access",
        "title": "Accès aux credentials système",
        "indicators": [
            "aud_credential_access",
        ],
        "description": (
            "Accès aux fichiers sensibles contenant des credentials : /etc/shadow, "
            "~/.ssh/id_rsa, ~/.aws/credentials, /proc/mem. "
            "Objectif : vol de mots de passe hashés pour cracking offline, "
            "ou récupération de clés privées pour mouvement latéral."
        ),
        "mitre": "T1003 — OS Credential Dumping / T1552 — Unsecured Credentials",
        "severity": "CRITICAL",
        "context": [
            "aud_credential_access : accès à /etc/shadow, /.ssh/id_rsa, /.aws/credentials",
            "is_root               : accès root augmente la dangerosité",
            "aud_cmd_entropy       : entropie élevée = outil obfusqué de dump",
        ],
        "remediation": [
            "Vérifier quel processus a accédé aux fichiers : ausearch -f /etc/shadow",
            "Forcer la rotation immédiate de tous les mots de passe système",
            "Révoquer et régénérer toutes les clés SSH présentes sur la machine",
            "Vérifier les hashes dans /etc/shadow contre des dictionnaires connus",
            "Auditer les connexions réseaux post-accès pour détecter une exfiltration",
        ],
    },
    {
        "id": "ssh_key_implant",
        "title": "Implantation de clé SSH",
        "indicators": [
            "aud_ssh_key_implant",
        ],
        "description": (
            "Écriture dans le fichier authorized_keys d'un utilisateur. "
            "Technique de persistance : l'attaquant ajoute sa clé publique pour "
            "garantir un accès futur même si le mot de passe est changé. "
            "Très difficile à détecter sans surveillance des fichiers."
        ),
        "mitre": "T1098.004 — SSH Authorized Keys / T1098 — Account Manipulation",
        "severity": "CRITICAL",
        "context": [
            "aud_ssh_key_implant : écriture dans authorized_keys détectée",
            "is_root             : si root, peut modifier les clés de tous les users",
            "cross_ssh_then_sudo : souvent couplé à une élévation de privilèges",
        ],
        "remediation": [
            "Inspecter immédiatement tous les fichiers authorized_keys du système",
            "Comparer avec une baseline connue ou un backup récent",
            "Supprimer les clés non autorisées",
            "Vérifier si d'autres machines du réseau ont été modifiées (mouvement latéral)",
            "Mettre en place une surveillance des fichiers authorized_keys (auditd watch)",
        ],
    },
    {
        "id": "ld_hijack",
        "title": "Hijacking de librairie dynamique",
        "indicators": [
            "aud_ld_hijack",
        ],
        "description": (
            "Manipulation de LD_PRELOAD ou /etc/ld.so.conf pour forcer le chargement "
            "d'une librairie malveillante avant les librairies légitimes. "
            "Permet d'intercepter des appels système (hooking), de cacher des processus "
            "ou d'escalader les privilèges. Technique de rootkit userland."
        ),
        "mitre": "T1574.006 — Dynamic Linker Hijacking / T1574 — Hijack Execution Flow",
        "severity": "CRITICAL",
        "context": [
            "aud_ld_hijack : LD_PRELOAD ou ld.so.conf modifié",
            "aud_process_injection : souvent combiné avec injection",
            "aud_sev_norm  : sévérité élevée si combiné avec root",
        ],
        "remediation": [
            "Vérifier les variables d'environnement : env | grep LD_",
            "Inspecter /etc/ld.so.conf et /etc/ld.so.conf.d/",
            "Lister les librairies préchargées : cat /proc/<pid>/maps",
            "Scanner les .so suspects : find / -name '*.so' -newer /var/log/dpkg.log",
            "Redémarrer les services critiques après nettoyage",
        ],
    },
    {
        "id": "kernel_module",
        "title": "Chargement de module kernel suspect",
        "indicators": [
            "sys_module_load",
        ],
        "description": (
            "Chargement d'un module kernel via insmod ou modprobe. "
            "Un module malveillant peut cacher des processus, des fichiers, "
            "des connexions réseau (rootkit kernel). Extrêmement difficile à détecter "
            "une fois installé car il opère au niveau du noyau."
        ),
        "mitre": "T1547.006 — Kernel Modules and Extensions / T1014 — Rootkit",
        "severity": "CRITICAL",
        "context": [
            "sys_module_load : insmod/modprobe/rmmod détecté dans syslog",
            "is_off_hours    : chargement hors heures = suspect",
            "is_root         : requis pour charger des modules",
        ],
        "remediation": [
            "Lister les modules chargés et comparer avec la baseline : lsmod | diff - baseline",
            "Vérifier la signature du module : modinfo <module>",
            "Activer le Secure Boot pour bloquer les modules non signés",
            "Analyser les appels système cachés : diff <(cat /proc/kallsyms) baseline_kallsyms",
            "Considérer un redémarrage depuis un support de confiance pour l'investigation",
        ],
    },
    {
        "id": "cron_backdoor",
        "title": "Backdoor via crontab",
        "indicators": [
            "aud_cron_backdoor",
            "sys_cron_new_job",
        ],
        "description": (
            "Création ou modification d'une tâche cron suspecte — téléchargement "
            "d'un script depuis un serveur externe, exécution depuis /tmp ou /dev/shm. "
            "Mécanisme de persistance classique : garantit la réexécution du payload "
            "même après redémarrage ou suppression manuelle."
        ),
        "mitre": "T1053.003 — Cron / T1053 — Scheduled Task/Job",
        "severity": "HIGH",
        "context": [
            "aud_cron_backdoor : crontab -e avec /tmp, wget, curl, bash -i",
            "sys_cron_new_job  : nouveau job créé via le scheduler système",
            "aud_exfiltration  : souvent couplé à une exfiltration programmée",
        ],
        "remediation": [
            "Inspecter toutes les crontabs : crontab -l -u <user> pour chaque utilisateur",
            "Vérifier /etc/cron.d/, /etc/cron.daily/, /var/spool/cron/",
            "Supprimer les tâches suspectes et les scripts associés",
            "Vérifier l'origine du téléchargement (URL/IP dans la commande cron)",
            "Mettre en place une surveillance des modifications crontab (auditd watch)",
        ],
    },
]


# =============================================================================
# SECTION B — FONCTION DE LOOKUP
# =============================================================================

def retrieve_knowledge_context(anomaly: dict) -> str:
    """
    Récupère les entrées pertinentes de la base de connaissances
    selon les flags actifs dans l'anomalie.

    Args:
        anomaly : document ES (avec ml.* ou structure plate)

    Returns:
        string formatée prête à être injectée dans le prompt LLM.
        Vide si aucun flag ne matche.

    Exemple :
        anomaly = {"ml": {"aud_reverse_shell": 1, "aud_cmd_is_obfuscated": 1}}
        → retourne la description complète de "reverse_shell"
    """
    # Cherche dans ml.* ou à la racine selon la structure du document
    ml = anomaly.get("ml", anomaly)

    matched = []
    seen_ids = set()   # évite les doublons si plusieurs flags matchent la même entrée

    # Indicateurs numériques (sévérité > 0 suffit)
    NUMERIC_INDICATORS = {"aud_severity", "aud_sev_norm", "auth_severity",
                          "auth_fail_count_5m", "aud_cmd_entropy"}

    for entry in THREAT_KNOWLEDGE:
        if entry["id"] in seen_ids:
            continue

        for indicator in entry["indicators"]:
            val = ml.get(indicator, 0)
            try:
                fval = float(val)
                # Pour les indicateurs numériques : > 0 suffit
                # Pour les flags binaires : == 1
                if indicator in NUMERIC_INDICATORS:
                    matched_flag = fval > 0
                else:
                    matched_flag = int(fval) == 1
                if matched_flag:
                    matched.append(entry)
                    seen_ids.add(entry["id"])
                    break
            except (ValueError, TypeError):
                continue

    if not matched:
        return ""

    # Formatage pour le prompt LLM
    sections = []
    for entry in matched:
        remediation_str = "\n".join(
            f"        {i+1}. {r}" for i, r in enumerate(entry["remediation"])
        )
        context_str = "\n".join(
            f"        - {c}" for c in entry.get("context", [])
        )

        section = f"""--- {entry['title']} [{entry['severity']}] ---
Description  : {entry['description']}
MITRE        : {entry['mitre']}
Signaux clés :
{context_str}
Actions      :
{remediation_str}"""
        sections.append(section)

    return "\n\n".join(sections)


def get_max_severity(anomaly: dict) -> str:
    """
    Retourne la sévérité maximale parmi les entrées matchées.
    Utile pour le scoring rapide sans appeler le LLM.

    Returns: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN"
    """
    ml = anomaly.get("ml", anomaly)
    SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    max_sev = "UNKNOWN"
    max_val = 0

    for entry in THREAT_KNOWLEDGE:
        for indicator in entry["indicators"]:
            val = ml.get(indicator, 0)
            try:
                fval = float(val)
                matched_flag = (fval > 0 if indicator in {"aud_severity","aud_sev_norm","auth_severity","auth_fail_count_5m","aud_cmd_entropy"} else int(fval) == 1)
                if matched_flag:
                    sev_val = SEVERITY_ORDER.get(entry["severity"], 0)
                    if sev_val > max_val:
                        max_val = sev_val
                        max_sev = entry["severity"]
                    break
            except (ValueError, TypeError):
                continue

    return max_sev


def get_matched_entries(anomaly: dict) -> list:
    """
    Retourne la liste des entrées matchées (dicts complets).
    Utile pour construire des alertes structurées.
    """
    ml = anomaly.get("ml", anomaly)
    matched = []
    seen_ids = set()

    for entry in THREAT_KNOWLEDGE:
        if entry["id"] in seen_ids:
            continue
        for indicator in entry["indicators"]:
            val = ml.get(indicator, 0)
            try:
                fval = float(val)
                matched_flag = (fval > 0 if indicator in {"aud_severity","aud_sev_norm","auth_severity","auth_fail_count_5m","aud_cmd_entropy"} else int(fval) == 1)
                if matched_flag:
                    matched.append(entry)
                    seen_ids.add(entry["id"])
                    break
            except (ValueError, TypeError):
                continue

    return matched