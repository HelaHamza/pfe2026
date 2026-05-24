#!/usr/bin/env python3
"""
Génère 100 logs (70 normaux / 30 malveillants) et les injecte dans le pipeline
syslog du système via `logger`, pour qu'ils atterrissent dans /var/log/auth.log
et /var/log/syslog, où Filebeat les lit -> Logstash(beats mTLS) -> ES.

auth   -> facility 'authpriv' (atterrit dans auth.log)
syslog -> facility 'user'     (atterrit dans syslog)

Écrit aussi groundtruth.jsonl = vérité terrain.

Usage:
  python3 loggen.py --seed 42
  python3 loggen.py --dry-run        # affiche les commandes sans rien injecter
"""
import argparse, json, random, subprocess, time
from datetime import datetime, timedelta

HOSTNAME="srv-app-01"
NORMAL_USERS=["alice","bob","carol","deploy","www-data"]
ADMIN_USERS=["alice","root"]
INTERNAL_IPS=[f"10.0.0.{i}" for i in range(10,40)]
ATTACKER_IP="185.220.101.45"
EXFIL_IP="45.155.205.233"
port=lambda:random.randint(40000,65000)

# logger gère lui-même l'horodatage et le hostname ; on ne fournit que le message.
def rec(source,msg,prog,sigma=None):
    return {"source":source,"prog":prog,"msg":msg,"sigma":sigma}

# ---- normaux ----
def normal():
    r=random.random()
    if r<0.45:
        u,ip=random.choice(NORMAL_USERS),random.choice(INTERNAL_IPS)
        return rec("auth",f"Accepted password for {u} from {ip} port {port()} ssh2","sshd")
    if r<0.65:
        u=random.choice(ADMIN_USERS)
        cmd=random.choice(["/usr/bin/apt update","/bin/systemctl restart nginx"])
        return rec("auth",f"{u} : TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND={cmd}","sudo")
    msg=random.choice(["Started Daily apt download activities.",
                       f"GET /api/health 200 {random.randint(1,40)}ms",
                       "Reached target Multi-User System."])
    return rec("syslog",msg,random.choice(["systemd","nginx","cron"]))

# ---- malveillants (mappés Sigma) ----
def bruteforce():
    out,u=[],random.choice(["root","admin","oracle"])
    for _ in range(8):
        inv="invalid user " if u in ("admin","oracle") else ""
        out.append(rec("auth",f"Failed password for {inv}{u} from {ATTACKER_IP} port {port()} ssh2","sshd","ssh_bruteforce"))
    return out
def privesc():
    out,u=[],random.choice(NORMAL_USERS)
    for _ in range(3):
        out.append(rec("auth",f"{u} : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash","sudo","sudo_auth_failure"))
    out.append(rec("auth",f"FAILED su for root by {u}","su","su_root"))
    return out
def exfil():
    tool=random.choice(["curl","nc","wget"])
    return [rec("syslog",f"OUTBOUND {tool} -> {EXFIL_IP}:443 bytes={random.randint(5_000_000,80_000_000)}","firewall","suspicious_outbound")]

SCENARIOS=[bruteforce,privesc,exfil]

def build_100():
    recs=[]
    while len([r for r in recs if r["sigma"]])<30:
        recs.extend(random.choice(SCENARIOS)())
    mal=[r for r in recs if r["sigma"]][:10]
    nrm=[normal() for _ in range(50)]
    allr=mal+nrm
    random.shuffle(allr)
    return allr

def inject(r,dry):
    # authpriv -> /var/log/auth.log ; user -> /var/log/syslog
    facility="authpriv" if r["source"]=="auth" else "user"
    tag=r["prog"]
    cmd=["logger","-p",f"{facility}.info","-t",tag,r["msg"]]
    if dry:
        print(" ".join(cmd)); return
    subprocess.run(cmd,check=False)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--seed",type=int,default=None)
    ap.add_argument("--dry-run",action="store_true")
    ap.add_argument("--delay",type=float,default=0.05,help="pause entre logs (s)")
    args=ap.parse_args()
    if args.seed is not None: random.seed(args.seed)

    recs=build_100()
    with open("groundtruth.jsonl","w") as f:
        for r in recs: f.write(json.dumps(r)+"\n")

    for r in recs:
        inject(r,args.dry_run)
        if not args.dry_run: time.sleep(args.delay)

    n_mal=sum(1 for r in recs if r["sigma"])
    by_src={}
    for r in recs: by_src[r["source"]]=by_src.get(r["source"],0)+1
    print(f"[+] {len(recs)} logs {'(dry-run) ' if args.dry_run else ''}— {len(recs)-n_mal} normaux / {n_mal} malveillants")
    print(f"    par source: {by_src}")
    print(f"    groundtruth.jsonl écrit")

if __name__=="__main__":
    main()