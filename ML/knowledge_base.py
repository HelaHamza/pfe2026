# knowledge_base.py
THREAT_KNOWLEDGE = [
    {
        "id": "brute_force_ssh",
        "title": "Brute Force SSH",
        "indicators": ["auth_is_brute_force", "auth_fail_count_5m", "auth_ip_is_external"],
        "description": (
            "Tentatives répétées de connexion SSH depuis une IP externe. "
            "Typiquement >10 échecs en 5 minutes. Peut précéder une intrusion réussie."
        ),
        "mitre": "T1110 - Brute Force",
        "severity": "HIGH",
        "remediation": [
            "Bloquer l'IP source dans le firewall",
            "Activer fail2ban ou équivalent",
            "Vérifier si une connexion a réussi après les échecs",
            "Vérifier les logs sudo post-connexion"
        ]
    },
    {
        "id": "privilege_escalation",
        "title": "Élévation de privilèges",
        "indicators": ["auth_sudo_to_root", "aud_ptrace", "aud_suid_abuse", "is_root"],
        "description": (
            "Processus tentant d'acquérir les droits root via sudo, "
            "ptrace ou exploitation de binaires SUID."
        ),
        "mitre": "T1548 - Abuse Elevation Control Mechanism",
        "severity": "CRITICAL",
        "remediation": [
            "Identifier le processus source (PID, commande)",
            "Vérifier les binaires SUID modifiés récemment",
            "Auditer les règles sudoers",
            "Isoler la machine si compromission confirmée"
        ]
    },
    {
        "id": "log_tampering",
        "title": "Falsification de logs",
        "indicators": ["aud_log_tamper", "aud_log_delete", "sys_log_tamper"],
        "description": (
            "Suppression ou modification des fichiers de logs système. "
            "Indicateur fort de post-exploitation — l'attaquant efface ses traces."
        ),
        "mitre": "T1070 - Indicator Removal on Host",
        "severity": "CRITICAL",
        "remediation": [
            "Vérifier l'intégrité des logs via un SIEM externe",
            "Identifier quel utilisateur/processus a touché les logs",
            "Corréler avec d'autres événements récents",
            "Initier une réponse à incident immédiate"
        ]
    },
    {
        "id": "reverse_shell",
        "title": "Reverse Shell",
        "indicators": ["aud_reverse_shell", "aud_cmd_is_obfuscated", "msg_has_base64"],
        "description": (
            "Commande obfusquée ou encodée en base64 ouvrant une connexion "
            "sortante vers un serveur distant. Technique classique de C2."
        ),
        "mitre": "T1059 - Command and Scripting Interpreter",
        "severity": "CRITICAL",
        "remediation": [
            "Identifier l'IP de destination de la connexion sortante",
            "Bloquer la connexion au niveau réseau",
            "Analyser le processus parent",
            "Rechercher la persistance (cron, systemd, .bashrc)"
        ]
    },
    {
        "id": "lateral_movement",
        "title": "Mouvement latéral SSH",
        "indicators": ["sys_lateral_ssh", "cross_ssh_then_sudo", "cross_multi_source"],
        "description": (
            "Connexions SSH internes inhabituelles suggérant un mouvement "
            "latéral après compromission initiale."
        ),
        "mitre": "T1021.004 - Remote Services: SSH",
        "severity": "HIGH",
        "remediation": [
            "Cartographier les connexions SSH internes récentes",
            "Vérifier les clés SSH autorisées sur chaque machine",
            "Chercher des clés SSH implantées (aud_ssh_key_implant)",
            "Segmenter le réseau si compromission avérée"
        ]
    },
    {
        "id": "data_exfiltration",
        "title": "Exfiltration de données",
        "indicators": ["aud_exfiltration", "aud_network_scan", "payload_size_log"],
        "description": (
            "Transfert anormal de données vers l'extérieur, "
            "souvent précédé d'un scan réseau interne."
        ),
        "mitre": "T1041 - Exfiltration Over C2 Channel",
        "severity": "CRITICAL",
        "remediation": [
            "Identifier les fichiers/répertoires accédés",
            "Analyser le volume et la destination du trafic sortant",
            "Bloquer les connexions sortantes non autorisées",
            "Alerter le responsable de la protection des données"
        ]
    },
    {
        "id": "cryptominer",
        "title": "Cryptominage malveillant",
        "indicators": ["aud_cryptominer", "sys_high_cpu_process"],
        "description": (
            "Processus utilisant intensivement le CPU, "
            "caractéristique d'un cryptominer déployé après intrusion."
        ),
        "mitre": "T1496 - Resource Hijacking",
        "severity": "MEDIUM",
        "remediation": [
            "Identifier et tuer le processus suspect",
            "Rechercher le vecteur d'installation (cron, service)",
            "Vérifier les comptes utilisateurs créés récemment",
            "Scanner les binaires modifiés"
        ]
    },
]