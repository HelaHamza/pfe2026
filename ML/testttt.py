from dotenv import load_dotenv
import os, ssl, json, base64, urllib.request

load_dotenv("/home/hala-hamza/pfe-backend-2026/.env")
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
token = base64.b64encode(f"elastic:{os.getenv('ELASTIC_PWD')}".encode()).decode()
headers = {"Content-Type": "application/json", "Authorization": f"Basic {token}"}

def req_json(path, body=None):
    url = f"https://localhost:9200{path}"
    data = json.dumps(body).encode() if body else None
    r = urllib.request.Request(url, data=data or b"",
                               headers=headers,
                               method="POST" if body else "GET")
    return json.loads(urllib.request.urlopen(r, context=ctx).read())

# 1. Tous les syscalls distincts présents dans ES
print("=== SYSCALLS PRÉSENTS DANS ES ===")
r = req_json("/auditbeat-*/_search", {
    "size": 0,
    "aggs": {
        "syscalls": {
            "terms": {"field": "auditd.data.syscall.keyword",
                      "size": 20}
        }
    }
})
for b in r.get("aggregations", {}).get("syscalls", {}).get("buckets", []):
    print(f"  {b['key']:20s} : {b['doc_count']:,}")

# 2. event.dataset distincts
print("\n=== EVENT.DATASET PRÉSENTS ===")
r = req_json("/auditbeat-*/_search", {
    "size": 0,
    "aggs": {
        "datasets": {
            "terms": {"field": "event.dataset.keyword", "size": 20}
        }
    }
})
for b in r.get("aggregations", {}).get("datasets", {}).get("buckets", []):
    print(f"  {b['key']:30s} : {b['doc_count']:,}")

# 3. Cherche execve SANS filtre dataset
print("\n=== DOCS execve (sans filtre dataset) ===")
r = req_json("/auditbeat-*/_search", {
    "size": 2,
    "query": {
        "term": {"auditd.data.syscall.keyword": "execve"}
    },
    "_source": ["@timestamp", "auditd.data.syscall",
                "auditd.data.a0", "auditd.data.a1",
                "process.args", "process.executable",
                "ml.log_source", "ml.aud_cmd_entropy"]
})
hits = r["hits"]["hits"]
print(f"Trouvés : {r['hits']['total']['value']}")
for h in hits:
    print(json.dumps(h["_source"], indent=2))
    print("---")

# 4. Dernier doc auditbeat toutes sources confondues
print("\n=== DERNIER DOC AUDITBEAT (tous types) ===")
r = req_json("/auditbeat-*/_search", {
    "size": 1,
    "sort": [{"@timestamp": {"order": "desc"}}],
    "query": {"match_all": {}}
})
hits = r["hits"]["hits"]
if hits:
    print(json.dumps(hits[0]["_source"], indent=2))
