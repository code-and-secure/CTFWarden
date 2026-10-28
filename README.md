<p align="center"><img src="static/brand/ctfwarden-wordmark.svg" width="420" alt="CTFWarden"></p>

# CTFWarden: lightweight monitor for a Docker-based CTFd event

CTFWarden is one Python process (~40–80 MB RAM) with no database server and no agents. It has a password-protected web dashboard, JSON and CSV APIs, and history kept in SQLite.

## What it shows

| Area | What you get |
|---|---|
| **Containers** | Every container with state, uptime, CPU %, memory, PIDs, net rx/tx, disk r/w, **writable-layer size and total size**, ports. Platform vs challenge is labelled. |
| **Who accessed what** | From the kernel conntrack table: **every client IP → container** (including nc/pwn challenges, not only HTTP), first/last seen and connection count. |
| **Pivots / escapes** | It alerts when a **challenge container connects to CTFd/DB/Redis** or to another player's instance, reaches a **host service** (e.g. 172.17.0.1:22), or opens an **outbound internet connection** (reverse shell / exfil). |
| **Docker events** | Create/start/die/OOM, crash loops, and **`docker exec` / attach / cp / commit / export** on any container. Healthcheck execs are filtered out. |
| **Web traffic** | Reads host nginx's existing access logs, read-only and auto-discovered. It keeps per-IP request counts, 4xx/404/429 counts and peak req/min, and lists the user agents and targets each IP used. |
| **Suspicious IPs** | Scanners (sqlmap, nikto, ffuf…), traversal/SQLi/XSS/SSTI/cmd-injection/log4shell probes, `.git`/`.env` hunting, `/admin` probing, **CTFd login brute force**, **mass registration** (multi-accounting), **flag brute force**, dir-busting and request floods. |
| **Host** | SSH logins (who/which IP/key), SSH brute force, and `sudo docker exec …` (this tells you *which admin* shelled into a container). It also tracks host CPU, RAM and disk. |
| **Live activity map** | On the Overview tab: a world map of the last 24 h. **All activity** (the default) shows every SSH login, failed or scanned SSH attempt, and connection or request to a container, at most once per IP/target per minute, plus every detection. The dashboard watches itself as well: visits, logins, failed logins (`dashboard-login-fail`) and 5+ failures in 10 min (`dashboard-bruteforce`, high). Your trusted IPs appear in teal. **Attacks only** shows medium/high detections from untrusted IPs. Countries are shaded by event count, and each new event animates an arc from its city to your server. Next to the map are the top source countries (with flags), top activity types, most-targeted containers and a real-time feed. |
| **Risky configs** | Flags challenge containers that are privileged, have `docker.sock` mounted, use host network/pid, carry dangerous caps, or have no memory/PIDs limit. |

Attack patterns aimed **at challenges** are recorded as `low` and don't raise the IP's score, because attacking challenges is the game. The same patterns aimed **at CTFd itself** are `high`.

Scoring works like this: `medium` adds 3 points and `high` adds 10. An IP is "suspicious" at 15 or more (`CTFMON_SUSPICIOUS`). Each rule counts at most once per minute per IP.

## Install (5 minutes)

```bash
# on the VM, as root
unzip ctfmon.zip -d /opt/ && cd /opt/ctfmon
nano docker-compose.yml                     # set CTFMON_PASSWORD, CTFMON_TRUSTED (your IP), webhook
modprobe nf_conntrack                       # usually already loaded because Docker uses NAT
docker compose up -d --build
docker logs -f ctfmon
```

Open it from your laptop through an SSH tunnel (nothing gets exposed publicly):

```bash
ssh -L 9999:127.0.0.1:9999 azureuser@<vm-ip>
# then browse http://127.0.0.1:9999 and sign in on the login page (user: admin, password from compose)
```

The **Overview → Data sources** table shows whether each feed is working: `docker`, `docker-events`, `conntrack`, `log:ctfd-v388-nginx-1` and `auth-log`.

### Without Docker

```bash
pip install "docker>=7"
sudo CTFMON_PASSWORD=... CTFMON_DB=/opt/ctfmon/ctfmon.db python3 ctfmon.py
```

## Your setup: host nginx in front of everything (nothing gets changed)

CTFWarden **never modifies nginx**. It only reads `/etc/nginx` and `/var/log` through read-only mounts. No config edits are needed, and no reload or restart either.

Players connect to `public-ip:33xxx` (challenges) or to CTFd's port, and host nginx forwards to `127.0.0.1:328xx` or `172.17.0.1:8000`. CTFWarden recovers the real player IP for every container from three independent sources:

| Source | What it gives |
|---|---|
| **nginx config** (re-read every 15 s) | public port → upstream → container, e.g. `:33001 → 127.0.0.1:32846 → reverent_davinci`. It also records **which `access_log` file belongs to which `server {}`**. |
| **conntrack** | every TCP connection `player-ip → :33xxx`, attributed to the container behind that port. This covers HTTP and nc/pwn, even if a server has logging turned off. |
| **your existing access logs** | found automatically from the `access_log` lines in the config (plus `/var/log/nginx/access.log`), in whatever format they already use. Lines come in per request with path, status, user agent and attack patterns. |

### How each log line is matched to a container

1. If the log file belongs to a single `server {}` block, the line goes to that block's container.
2. Otherwise the line is in a shared log such as `access.log`. If the path is a CTFd route (`/api/v1/`, `/login`, `/challenges`, `/scoreboard`, `/admin`, …), it goes to **CTFd**, where attacks are scored `high`.
3. Otherwise it goes to the challenge instance that IP connected to in the last 3 minutes, according to conntrack.

Stream (TCP) logs work in the default `key=value` style or the common `$remote_addr [$time_local] … "$upstream_addr"` style. If a stream server has no log, conntrack still covers it.

### Path labels in the container's "Who connected" view

- `nginx :33001` / `nginx log`: a real player through nginx
- `direct`: a real IP hitting a published `0.0.0.0` port
- `localhost`: from the VM itself. This is nginx's own hop, or someone on the box running `curl 127.0.0.1:328xx`. It's listed but never counted as a player.
- `host/proxy`: Docker's internal proxy hop

If your nginx config lives somewhere other than `/etc/nginx`, change that mount in compose and set `CTFMON_NGINX_CONF` to match. Check **Overview → Data sources**: `nginx-config` shows how many ports it mapped, and each discovered log shows as `log /host/var/log/nginx/...`.

## Settings (env vars)

| Var | Default | Meaning |
|---|---|---|
| `CTFMON_PASSWORD` | random (printed in log) | dashboard password (user `admin`, `CTFMON_USER` to change) |
| `CTFMON_TRUSTED` | `127.0.0.0/8,::1/128` | admin IPs/CIDRs, never flagged |
| `CTFMON_PLATFORM` | your CTFd/db/redis/nginx/scoreboard/validator names | everything else counts as a challenge |
| `CTFMON_LOG_CONTAINERS` | – | optional: containers whose stdout is an access log |
| `CTFMON_LOG_FILES` | – | extra log files (nginx access logs are auto-discovered from the config) |
| `CTFMON_CTFD_CONTAINER` | `ctfd-v388-ctfd-1` | where CTFd-route requests in shared logs are attributed |
| `CTFMON_NGINX_CONF` | `/host/etc/nginx` | host nginx config dir to build the public-port → container map |
| `CTFMON_PUBLIC_IP` | – | VM public IP(s), so instance → public-IP traffic is recognised |
| `CTFMON_MAP_HOME` | geolocated | `lat,lon[,label]` of your server on the attack map. Without it, the server is geolocated from `CTFMON_PUBLIC_IP` (or its outgoing IP) |
| `CTFMON_FILE_ROLE` | `challenge` | how to score requests in LOG_FILES that can't be attributed |
| `CTFMON_CONN_PER_MIN` | 120 | TCP sessions/min from one IP before `conn-flood` |
| `CTFMON_WEBHOOK` | – | Discord/Slack webhook for HIGH alerts (max 20/min, @mentions disabled) |
| `CTFMON_LINK_ALLOW` | validator | where challenges may connect without alerting |
| `CTFMON_EGRESS_ALLOW` | – | internet CIDRs challenges may reach (e.g. for SSRF challenges) |
| `CTFMON_EXEC_IGNORE` | – | regex of your automation's `docker exec` commands |
| `CTFMON_RATE_PER_MIN` | 600 | req/min from one IP before "high-rate" |
| `CTFMON_LOGIN_FAILS` | 15 | failed CTFd logins / 10 min |
| `CTFMON_NOTFOUND_5MIN` | 150 | 404s / 5 min (dir busting) |
| `CTFMON_SSH_FAILS` | 10 | failed SSH / 10 min |
| `CTFMON_DISK_MB` | 500 | container writable-layer size alert |
| `CTFMON_CPU_PCT` / `MEM_PCT` / `PIDS_MAX` | 90 / 90 / 300 | per-container resource alerts (PIDs = fork bomb) |
| `CTFMON_INTEL` | 1 | IP lookups on/off |
| `CTFMON_INTEL_SCOPE` | all | `all` = geolocate everyone, `flagged` = only IPs that triggered a rule |
| `CTFMON_PROXYCHECK_KEY` | – | proxycheck.io key (VPN provider names, 1000/day) |
| `CTFMON_ABUSEIPDB_KEY` | – | AbuseIPDB key (abuse reputation, 1000/day) |
| `CTFMON_STATS_EVERY` / `SIZE_EVERY` / `CONN_EVERY` | 10 / 300 / 5 s | polling intervals |

**Note about players behind NAT:** many of your 700 players may share one IP (a university or office). Raise `CTFMON_RATE_PER_MIN` if legit traffic gets flagged, and treat `mass-registration` from a campus IP with judgement.

## Who is the attacker? (IP lookups)

Every public IP gets a location, and every IP that triggers a rule (SSH brute force, scanners, injections…) gets a **full lookup**. You see it in the **Location / network** column of the IPs tab, in the **Who is this** section when you open an IP, in alert and webhook messages, and in `/export/ips.csv`.

| Field | Source |
|---|---|
| Country, region, city, postcode, coordinates, timezone | ip-api.com (free, no key) |
| ISP, organisation, ASN, reverse DNS | ip-api.com + local reverse DNS |
| **VPN / proxy**, **datacenter / cloud server**, mobile network | ip-api.com + proxycheck.io |
| **VPN provider name** (NordVPN, Mullvad…) and proxy risk % | proxycheck.io (100/day keyless, 1000/day with a free key) |
| **Tor exit node** | official Tor exit list, refreshed every 6 h |
| **Abuse reputation**: confidence %, number of reports, attack categories | AbuseIPDB (optional free key) |
| SSH: every **username tried**, failed-attempt count, **successful logins with the key fingerprint**, scanner notes | your auth.log |
| One-click links to AbuseIPDB, Shodan, VirusTotal, GreyNoise, ipinfo, Censys, RDAP/WHOIS (shows the ISP's abuse contact) | – |

What an IP **can't** tell you: the attacker's PC name, username, MAC address or exact street address. None of that travels over SSH or HTTP. Location is city-level at best. If the IP is a VPN/Tor/datacenter, you only learn about the VPN or server, not the person behind it. Most SSH brute force comes from infected servers and botnets, not from the person who controls them. CTFWarden only does passive lookups and never probes the attacker's machine.

Privacy: with `CTFMON_INTEL_SCOPE=all`, players' IPs are sent to ip-api.com. Your trusted IPs are sent there too, for location only, so they can appear on the live map. They never get VPN or abuse lookups. Set it to `flagged` to only look up IPs that triggered a rule, or `CTFMON_INTEL=0` to turn lookups off. Results are cached in SQLite for 7 days (`CTFMON_INTEL_TTL_DAYS`).

## Blocking an IP

Each IP's detail view shows the commands to use:

```bash
iptables -I DOCKER-USER -s 1.2.3.4 -j DROP   # traffic to containers (incl. CTFd on :81)
iptables -I INPUT       -s 1.2.3.4 -j DROP   # host (SSH)
```

CTFWarden itself is read-only and never blocks anything on its own.

## Exports for after the event

`/export/ips.csv`, `/export/access.csv` (container ↔ IP) and `/export/alerts.csv`. The full history is in `data/ctfmon.db` (SQLite).

## Security notes

- CTFWarden needs `docker.sock`, which is root-equivalent even when mounted read-only. Keep it on `127.0.0.1` and use the SSH tunnel.
- All log-derived text is HTML-escaped and the page runs under a strict CSP, so a player can't plant XSS in your dashboard through a user agent.
- `docker exec` events don't record *who* ran them. CTFWarden correlates them with `sudo` lines in auth.log. If you work as `root` directly, add `auditd -w /usr/bin/docker -k docker` for full attribution.

## Good companions (optional)

- **CrowdSec**: reads the same nginx log and can **auto-ban** IPs, which CTFWarden deliberately doesn't do.
- **Dozzle**: a live log viewer for any container, useful for debugging a broken challenge.
