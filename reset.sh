Script démarré sur 2026-05-20 22:48:04+01:00 [TERM="xterm-256color" TTY="/dev/pts/3" COLUMNS="181" LINES="19"]
[?2004h]0;hala-hamza@ASUS-X415JA: ~/pfe-backend-2026[01;32mhala-hamza@ASUS-X415JA[00m:[01;34m~/pfe-backend-2026[00m$ python3 -m backend.mainsource ~/pfe-venv/bin/activate 
[?2004l[?2004h(pfe-venv) ]0;hala-hamza@ASUS-X415JA: ~/pfe-backend-2026[01;32mhala-hamza@ASUS-X415JA[00m:[01;34m~/pfe-backend-2026[00m$ bash resetsg[Kh[K[K.sh
[?2004l[?2004h(pfe-venv) ]0;hala-hamza@ASUS-X415JA: ~/pfe-backend-2026[01;32mhala-hamza@ASUS-X415JA[00m:[01;34m~/pfe-backend-2026[00m$ bash reset.sh
[?2004l=== Curseur actuel ===
{
    "_index": "ids-pipeline-cursor",
    "_id": "last_run",
    "_version": 14,
    "_seq_no": 13,
    "_primary_term": 7,
    "found": true,
    "_source": {
        "last_timestamp": "2026-05-20T14:22:39.105Z",
        "updated_at": "2026-05-20T14:26:22.030004+00:00"
    }
}

=== Nb alertes Sigma totales ===
{
    "count": 10238,
    "_shards": {
        "total": 1,
        "successful": 1,
        "skipped": 0,
        "failed": 0
    }
}

=== Nb alertes DEPUIS le curseur (7j) ===
{
    "count": 4406,
    "_shards": {
        "total": 1,
        "successful": 1,
        "skipped": 0,
        "failed": 0
    }
}

=== Timestamp max des alertes Sigma ===
2026-05-20T21:46:48Z
[?2004h(pfe-venv) ]0;hala-hamza@ASUS-X415JA: ~/pfe-backend-2026[01;32mhala-hamza@ASUS-X415JA[00m:[01;34m~/pfe-backend-2026[00m$ bash reset.shsource ~/pfe-venv/bin/activate [8Ppython3 -m backend.main
[?2004l[32mINFO[0m:     Will watch for changes in these directories: ['/home/hala-hamza/pfe-backend-2026']
[32mINFO[0m:     Uvicorn running on [1mhttp://0.0.0.0:8000[0m (Press CTRL+C to quit)
[32mINFO[0m:     Started reloader process [[36m[1m15075[0m] using [36m[1mStatReload[0m
[32mINFO[0m:     Started server process [[36m15167[0m]
[32mINFO[0m:     Waiting for application startup.
[32mINFO[0m:     Application startup complete.
[32mINFO[0m:     127.0.0.1:46460 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46452 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46460 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46442 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46486 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46468 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46472 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46452 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46468 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46460 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46442 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46486 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46468 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46472 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46452 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46442 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46460 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46486 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46452 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46468 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46472 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:46442 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53866 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53862 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53876 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53844 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53846 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53870 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53866 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53862 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53870 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53844 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53876 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53846 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53866 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53862 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53870 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53866 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53844 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53846 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53876 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53862 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53870 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53866 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:34898 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53866 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53862 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:34928 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53870 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:34898 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:34912 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53866 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53862 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:34912 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:34928 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53870 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:34898 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53866 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:34898 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:34928 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53862 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53866 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:34912 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53870 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:34898 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:34928 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:34928 - "[1mPOST /run/analyse HTTP/1.1[0m" [32m200 OK[0m
[AnalyseController] Analyse déjà en cours — abandon
[32mINFO[0m:     127.0.0.1:34928 - "[1mGET /run/analyse/stream HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39524 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39498 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39518 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39544 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39510 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39538 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39538 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39524 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39518 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39498 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39510 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39544 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39538 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39524 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39518 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39498 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39544 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39538 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39524 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39510 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39518 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39498 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39524 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39498 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39510 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39544 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39518 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39524 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39538 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39498 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39524 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39510 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39544 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39518 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39538 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39498 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39524 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39510 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39544 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39518 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39498 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39538 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39524 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39510 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39498 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39510 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39538 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39524 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39498 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39544 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39518 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39544 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39510 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39538 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39524 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39498 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39518 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39544 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39510 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39538 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39524 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39498 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39518 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39544 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39510 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:39538 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47336 - "[1mPOST /run/analyse HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47368 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47386 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47336 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47364 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47352 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47368 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47370 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47370 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47336 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47386 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47364 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47352 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47368 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47370 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47336 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47386 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47364 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47368 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47370 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47352 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47336 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:47386 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
^C[32mINFO[0m:     Shutting down
[32mINFO[0m:     Waiting for application shutdown.
[32mINFO[0m:     Application shutdown complete.
[32mINFO[0m:     Finished server process [[36m15167[0m]
[32mINFO[0m:     Stopping reloader process [[36m[1m15075[0m]
[?2004h(pfe-venv) ]0;hala-hamza@ASUS-X415JA: ~/pfe-backend-2026[01;32mhala-hamza@ASUS-X415JA[00m:[01;34m~/pfe-backend-2026[00m$ python3 -m backend.main[K[Kpython3 -m backend.mai[K[K[K[K[K[K[K[K[K[K[K[K[K[Ktest.py
[?2004l
── Connexion Elasticsearch ──
  ✓ Cluster 'pfe-2026' — status: yellow

── Injection logs bruts (filebeat-logs-test) ──
  ✓ 45/45 logs insérés

── Injection anomalies AE (ml-autoencoder-scores) ──
  ✓ 12/12 anomalies insérées

── Injection alertes Sigma (sigma-alerts) ──
  ✓ 20/20 alertes insérées

── Refresh indices ──
  ✓ Indices rafraîchis

── Mise à jour curseur + report MongoDB ──
  ✓ Curseur mis à 2026-05-20T21:54:37.000Z
[MongoDB] Report sauvegardé : 6a0e2ff8b524fdedc8865976
  ✓ Report MongoDB créé : 6a0e2ff8b524fdedc8865976

════════════════════════════════════════════════════════════
VÉRIFICATION — ce que le dashboard devrait afficher
════════════════════════════════════════════════════════════
  ✓  Alertes Sigma totales                    20
  ✓    Sigma CRITICAL                         5
  ✓    Sigma HIGH                             8
  ✓    Sigma MEDIUM                           4
  ✓    Sigma LOW                              3
  ✓  Anomalies AE totales                     12
  ✓    AE anomalies SYSLOG                    3
  ✓    AE anomalies AUTH                      7
  ✓    AE anomalies AUDITD                    2
  ✓    Logs bruts SYSLOG                      15
  ✓    Logs bruts AUTH                        20
  ✓    Logs bruts AUDITD                      10

────────────────────────────────────────────────────────────
  Résultat : 12 ✓  |  0 ✗
  🎉 Toutes les vérifications passent — dashboard prêt
────────────────────────────────────────────────────────────

VALEURS ATTENDUES DANS LE DASHBOARD :
  ┌─────────────────────────────────────────────────────┐
  │  KPIs                                               │
  │    Alertes critiques  : 5   (fond rouge)            │
  │    Alertes Sigma      : 20                          │
  │    Anomalies AE       : 12                          │
  │    Corrélées AE+Σ     : 0                           │
  ├─────────────────────────────────────────────────────┤
  │  Sigma severity                                     │
  │    CRITICAL : 5  ██████░░░░░░░░░░                  │
  │    HIGH     : 8  █████████████░░░                  │
  │    MEDIUM   : 4  ██████░░░░░░░░░░                  │
  │    LOW      : 3  ████░░░░░░░░░░░░                  │
  ├─────────────────────────────────────────────────────┤
  │  Logs & anomalies AE                                │
  │    SYSLOG  : 15 logs  · 3 anomalies                │
  │    AUTH    : 20 logs  · 7 anomalies                 │
  │    AUDITD  : 10 logs  · 2 anomalies                 │
  ├─────────────────────────────────────────────────────┤
  │  MITRE ATT&CK top tactiques                         │
  │    Initial Access     : 4                           │
  │    Credential Access  : 3                           │
  │    Persistence        : 3                           │
  │    Impact             : 2                           │
  │    Reconnaissance     : 2                           │
  └─────────────────────────────────────────────────────┘


Étapes suivantes :
  1. Redémarrez le backend : python3 -m backend.main
  2. Rechargez le dashboard
  3. Comparez les valeurs affichées avec le tableau ci-dessus
  4. Pour nettoyer : python3 inject_test_data.py --reset

[?2004h(pfe-venv) ]0;hala-hamza@ASUS-X415JA: ~/pfe-backend-2026[01;32mhala-hamza@ASUS-X415JA[00m:[01;34m~/pfe-backend-2026[00m$ python3 test.py-m backend.main
[?2004l[32mINFO[0m:     Will watch for changes in these directories: ['/home/hala-hamza/pfe-backend-2026']
[32mINFO[0m:     Uvicorn running on [1mhttp://0.0.0.0:8000[0m (Press CTRL+C to quit)
[32mINFO[0m:     Started reloader process [[36m[1m19578[0m] using [36m[1mStatReload[0m
[32mINFO[0m:     Started server process [[36m19663[0m]
[32mINFO[0m:     Waiting for application startup.
[32mINFO[0m:     Application startup complete.
[32mINFO[0m:     127.0.0.1:54412 - "[1mPOST /run/analyse HTTP/1.1[0m" [32m200 OK[0m
[AnalyseController] Analyse déjà en cours — abandon
[32mINFO[0m:     127.0.0.1:54412 - "[1mGET /run/analyse/stream HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:40024 - "[1mPOST /run/reset HTTP/1.1[0m" [31m404 Not Found[0m
[33mWARNING[0m:  StatReload detected changes in 'backend/api.py'. Reloading...
[32mINFO[0m:     Shutting down
[32mINFO[0m:     Waiting for connections to close. (CTRL+C to force quit)
^C^[[A    ^C^C^C^C^C^C[32mINFO[0m:     Finished server process [[36m19663[0m]
[31mERROR[0m:    Traceback (most recent call last):
  File "/usr/lib/python3.12/asyncio/runners.py", line 194, in run
    return runner.run(main)
           ^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/asyncio/runners.py", line 118, in run
    return self._loop.run_until_complete(task)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/asyncio/base_events.py", line 674, in run_until_complete
    self.run_forever()
  File "/usr/lib/python3.12/asyncio/base_events.py", line 641, in run_forever
    self._run_once()
  File "/usr/lib/python3.12/asyncio/base_events.py", line 1987, in _run_once
    handle._run()
  File "/usr/lib/python3.12/asyncio/evckend/api.py'. Reloading...
[32mINFO[0m:     Shutting down
[32mINFO[0m:     Waiting for connections to close. (CTRL+C to force quit)
^C^[[A    ^C^C^C^C^C^C[32mINFO[0m:     Finished server process [[36m19663[0m]
[31mERROR[0m:    Traceback (most recent call last):
  File "/usr/lib/python3.12/asyncio/runners.py", line 194, in run
    return runner.run(main)
           ^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/asyncio/runners.py", line 118, in run
    return self._loop.run_until_complete(task)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/asyncio/base_events.py", line 674, in run_until_complete
    self.run_forever()
  File "/usr/lib/python3.12/asyncio/base_events.py", line 641, in run_forever
    self._run_once()
  File "/usr/lib/python3.12/asyncio/base_events.py", line 1987, in _run_once
    handle._run()
  File "/usr/lib/python3.12/asyncio/events.py", line 88, in _run
    self._context.run(self._callback, *self._args)
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/uvicorn/server.py", line 78, in serve
    with self.capture_signals():
  File "/usr/lib/python3.12/contextlib.py", line 144, in __exit__
    next(self.gen)
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/uvicorn/server.py", line 339, in capture_signals
    signal.raise_signal(captured_signal)
  File "/usr/lib/python3.12/asyncio/runners.py", line 157, in _on_sigint
    raise KeyboardInterrupt()
KeyboardInterrupt

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/starlette/routing.py", line 645, in lifespan
    await receive()
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/uvicorn/lifespan/on.py", line 137, in receive
    return await self.receive_queue.get()
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/asyncio/queues.py", line 158, in get
    await getter
asyncio.exceptions.CancelledError

[31mERROR[0m:    Exception in ASGI application
Traceback (most recent call last):
  File "/usr/lib/python3.12/asyncio/runners.py", line 194, in run
    return runner.run(main)
           ^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/asyncio/runners.py", line 118, in run
    return self._loop.run_until_complete(task)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/asyncio/base_events.py", line 674, in run_until_complete
    self.run_forever()
  File "/usr/lib/python3.12/asyncio/base_events.py", line 641, in run_forever
    self._run_once()
  File "/usr/lib/python3.12/asyncio/base_events.py", line 1987, in _run_once
    handle._run()
  File "/usr/lib/python3.12/asyncio/events.py", line 88, in _run
    self._context.run(self._callback, *self._args)
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/uvicorn/server.py", line 78, in serve
    with self.capture_signals():
  File "/usr/lib/python3.12/contextlib.py", line 144, in __exit__
    next(self.gen)
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/uvicorn/server.py", line 339, in capture_signals
    signal.raise_signal(captured_signal)
  File "/usr/lib/python3.12/asyncio/runners.py", line 157, in _on_sigint
    raise KeyboardInterrupt()
KeyboardInterrupt

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/uvicorn/protocols/http/h11_impl.py", line 415, in run_asgi
    result = await app(  # type: ignore[func-returns-value]
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/uvicorn/middleware/proxy_headers.py", line 56, in __call__
    return await self.app(scope, receive, send)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/fastapi/applications.py", line 1159, in __call__
    await super().__call__(scope, receive, send)e-venv/lib/python3.12/site-packages/starlette/_exception_handler.py", line 42, in wrapped_app
    await app(scope, receive, sender)
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/fastapi/middleware/asyncexitstack.py", line 18, in __call__
    await self.app(scope, receive, send)
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/starlette/routing.py", line 660, in __call__
    await self.middleware_stack(scope, receive, send)
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/starlette/routing.py", line 680, in app
    await route.handle(scope, receive, send)
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/starlette/routing.py", line 276, in handle
    await self.app(scope, receive, send)
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/fastapi/routing.py", line 134, in app
    await wrap_app_handling_exceptions(app, request)(scope, receive, send)
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/starlette/_exception_handler.py", line 42, in wrapped_app
    await app(scope, receive, sender)
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/fastapi/routing.py", line 121, in app
    await response(scope, receive, send)
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/starlette/responses.py", line 274, in __call__
    async with anyio.create_task_group() as task_group:
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/anyio/_backends/_asyncio.py", line 803, in __aexit__
    raise exc_val
  File "/home/hala-hamza/pfe-venv/lib/python3.12/site-packages/anyio/_backends/_asyncio.py", line 771, in __aexit__
    await self._on_completed_fut
asyncio.exceptions.CancelledError
[32mINFO[0m:     Stopping reloader process [[36m[1m19578[0m]
[?2004h(pfe-venv) ]0;hala-hamza@ASUS-X415JA: ~/pfe-backend-2026[01;32mhala-hamza@ASUS-X415JA[00m:[01;34m~/pfe-backend-2026[00m$ python3 -m backend.main
[?2004l[32mINFO[0m:     Will watch for changes in these directories: ['/home/hala-hamza/pfe-backend-2026']
[32mINFO[0m:     Uvicorn running on [1mhttp://0.0.0.0:8000[0m (Press CTRL+C to quit)
[32mINFO[0m:     Started reloader process [[36m[1m22934[0m] using [36m[1mStatReload[0m
[32mINFO[0m:     Started server process [[36m22995[0m]
[32mINFO[0m:     Waiting for application startup.
[32mINFO[0m:     Application startup complete.
[32mINFO[0m:     127.0.0.1:54738 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[MongoDB] get_last_report error: No replica set members match selector "Primary()", Timeout: 5.0s, Topology Description: <TopologyDescription id: 6a0e33384ed2a2f9c5ed717d, topology_type: ReplicaSetNoPrimary, servers: [<ServerDescription ('ac-qe27fbw-shard-00-00.5bnu9hu.mongodb.net', 27017) server_type: RSSecondary, rtt: 0.0576375000000553>, <ServerDescription ('ac-qe27fbw-shard-00-01.5bnu9hu.mongodb.net', 27017) server_type: Unknown, rtt: None>, <ServerDescription ('ac-qe27fbw-shard-00-02.5bnu9hu.mongodb.net', 27017) server_type: Unknown, rtt: None>]>
[MongoDB] get_last_report error: No replica set members match selector "Primary()", Timeout: 5.0s, Topology Description: <TopologyDescription id: 6a0e33384ed2a2f9c5ed717b, topology_type: ReplicaSetNoPrimary, servers: [<ServerDescription ('ac-qe27fbw-shard-00-00.5bnu9hu.mongodb.net', 27017) server_type: RSSecondary, rtt: 0.11489063199996963>, <ServerDescription ('ac-qe27fbw-shard-00-01.5bnu9hu.mongodb.net', 27017) server_type: Unknown, rtt: None>, <ServerDescription ('ac-qe27fbw-shard-00-02.5bnu9hu.mongodb.net', 27017) server_type: Unknown, rtt: None>]>
[MongoDB] get_last_report error: No replica set members match selector "Primary()", Timeout: 5.0s, Topology Description: <TopologyDescription id: 6a0e33384ed2a2f9c5ed717f, topology_type: ReplicaSetNoPrimary, servers: [<ServerDescription ('ac-qe27fbw-shard-00-00.5bnu9hu.mongodb.net', 27017) server_type: RSSecondary, rtt: 0.10336615100004565>, <ServerDescription ('ac-qe27fbw-shard-00-01.5bnu9hu.mongodb.net', 27017) server_type: Unknown, rtt: None>, <ServerDescription ('ac-qe27fbw-shard-00-02.5bnu9hu.mongodb.net', 27017) server_type: Unknown, rtt: None>]>
[32mINFO[0m:     127.0.0.1:54748 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[MongoDB] get_last_report error: No replica set members match selector "Primary()", Timeout: 5.0s, Topology Description: <TopologyDescription id: 6a0e33394ed2a2f9c5ed7180, topology_type: ReplicaSetNoPrimary, servers: [<ServerDescription ('ac-qe27fbw-shard-00-00.5bnu9hu.mongodb.net', 27017) server_type: RSSecondary, rtt: 0.09113281600002665>, <ServerDescription ('ac-qe27fbw-shard-00-01.5bnu9hu.mongodb.net', 27017) server_type: Unknown, rtt: None>, <ServerDescription ('ac-qe27fbw-shard-00-02.5bnu9hu.mongodb.net', 27017) server_type: Unknown, rtt: None>]>
[MongoDB] get_last_report error: No replica set members match selector "Primary()", Timeout: 5.0s, Topology Description: <TopologyDescription id: 6a0e33384ed2a2f9c5ed717e, topology_type: ReplicaSetNoPrimary, servers: [<ServerDescription ('ac-qe27fbw-shard-00-00.5bnu9hu.mongodb.net', 27017) server_type: RSSecondary, rtt: 0.0797651049997512>, <ServerDescription ('ac-qe27fbw-shard-00-01.5bnu9hu.mongodb.net', 27017) server_type: Unknown, rtt: None>, <ServerDescription ('ac-qe27fbw-shard-00-02.5bnu9hu.mongodb.net', 27017) server_type: Unknown, rtt: None>]>
[MongoDB] get_last_report error: No replica set members match selector "Primary()", Timeout: 5.0s, Topology Description: <TopologyDescription id: 6a0e33384ed2a2f9c5ed717c, topology_type: ReplicaSetNoPrimary, servers: [<ServerDescription ('ac-qe27fbw-shard-00-00.5bnu9hu.mongodb.net', 27017) server_type: RSSecondary, rtt: 0.07914362000019537>, <ServerDescription ('ac-qe27fbw-shard-00-01.5bnu9hu.mongodb.net', 27017) server_type: Unknown, rtt: None>, <ServerDescription ('ac-qe27fbw-shard-00-02.5bnu9hu.mongodb.net', 27017) server_type: Unknown, rtt: None>]>
[32mINFO[0m:     127.0.0.1:54724 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54742 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54738 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54720 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54718 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54738 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54748 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54724 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54742 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54720 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54718 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54738 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54724 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54748 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54742 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54720 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54718 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54738 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54748 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54724 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:53820 - "[1mPOST /run/analyse HTTP/1.1[0m" [32m200 OK[0m
[AnalyseController] Analyse déjà en cours — abandon
[32mINFO[0m:     127.0.0.1:53820 - "[1mGET /run/analyse/stream HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54662 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54676 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54656 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54648 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54650 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54662 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54670 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54662 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54676 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54656 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54648 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54650 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54662 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54670 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54676 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54656 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54662 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54670 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54648 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54650 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54656 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54676 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48200 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48174 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48200 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48202 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48188 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48196 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48208 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48196 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48200 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48202 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48208 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48174 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48188 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48196 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48200 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48208 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48174 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48188 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48202 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48196 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48200 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48208 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54148 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54138 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48208 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54174 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54122 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54160 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54148 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54160 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48208 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54174 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54138 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54122 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54148 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54160 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48208 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54174 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54138 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54148 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54122 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54160 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:48208 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:54174 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38472 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38460 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38496 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38434 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38488 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38472 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38446 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38446 - "[1mGET /results?limit=500 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38460 - "[1mGET /reports/last HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38496 - "[1mGET /stats/sigma-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38434 - "[1mGET /stats/sigma-by-level HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38488 - "[1mGET /stats/anomalies-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38446 - "[1mGET /stats/logs-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38472 - "[1mGET /stats/by-tactic HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38460 - "[1mGET /stats HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38434 - "[1mGET /stats/attacks-by-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38496 - "[1mGET /stats/detection-source HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38488 - "[1mGET /stats/timeline?days=7 HTTP/1.1[0m" [32m200 OK[0m
[32mINFO[0m:     127.0.0.1:38446 - "[1mGET /repo