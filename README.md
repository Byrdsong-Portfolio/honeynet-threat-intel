# Honeynet Suite

**A multi-service honeypot system (SSH / HTTP / MySQL) for capturing, logging, and analyzing real-world attack behavior.**

Built as a defensive security portfolio project deployed on DigitalOcean, this suite emulates three commonly targeted services, logs every interaction to structured JSON, and feeds a live analysis dashboard tracking attacker behavior over time.

---

## Architecture

```
Internet
    |
    v
[ DigitalOcean Droplet: Ubuntu 22.04 ]
    |
    +--[ SSH Honeypot        :2222 ]  --> logs/ssh_events.jsonl
    |      - Fake banner (OpenSSH 7.4)
    |      - Logs IP, username, password, timestamp
    |      - Paramiko-based listener
    |
    +--[ HTTP Honeypot       :8080 ]  --> logs/http_events.jsonl
    |      - Fake Apache/2.4.41 header
    |      - Serves fake login page, admin panel, /phpmyadmin
    |      - Logs method, path, user-agent, POST body, IP
    |
    +--[ MySQL Honeypot      :3306 ]  --> logs/mysql_events.jsonl
    |      - Emulates MySQL 5.7 handshake
    |      - Logs auth attempts, client version, capabilities flags
    |      - Returns ERR_ACCESS_DENIED to all connections
    |
    +--[ Dashboard           :5000 ]  --> Flask + Chart.js
           - Real-time attack volume by service
           - Top attacking IPs (geo-resolved)
           - Top credentials attempted (SSH)
           - HTTP path heatmap
           - Attack timeline (hourly / daily / weekly)
```

---

## Features

| Feature | SSH | HTTP | MySQL |
|---|---|---|---|
| Connection logging | Yes | Yes | Yes |
| Credential capture | Yes | POST forms | Handshake auth |
| Fake service banner | OpenSSH 7.4 | Apache 2.4.41 | MySQL 5.7.38 |
| Structured JSON output | Yes | Yes | Yes |
| Geo-IP resolution | Yes | Yes | Yes |
| Rate limiting / block list | Yes | Yes | Yes |
| Dashboard integration | Yes | Yes | Yes |

---

## Project Structure

```
honeynet/
├── ssh_honeypot.py          # Paramiko SSH listener
├── http_honeypot.py         # Flask-based HTTP trap
├── mysql_honeypot.py        # Raw socket MySQL emulator
├── dashboard/
│   ├── app.py               # Flask dashboard server
│   ├── templates/
│   │   └── index.html       # Chart.js dashboard UI
│   └── static/
│       └── charts.js        # Chart configuration
├── utils/
│   ├── logger.py            # Structured JSON logger (shared)
│   ├── geoip.py             # IP geolocation helper
│   └── alerting.py          # Optional webhook/email alerts
├── fake_data/               # Runtime-generated bait (gitignored)
│   ├── employees.csv
│   ├── credentials.txt
│   └── dump.sql
├── logs/                    # All captured events (gitignored)
│   ├── ssh_events.jsonl
│   ├── http_events.jsonl
│   └── mysql_events.jsonl
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- A Linux VPS with ports 2222, 3306, 5000, 8080 accessible
- Root or sudo access to bind service ports

### Installation

```bash
git clone https://github.com/Byrdsong-Portfolio/honeynet.git
cd honeynet
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Running Each Service

```bash
# SSH honeypot (background)
nohup python3 ssh_honeypot.py > /dev/null 2>&1 &

# HTTP honeypot (background)
nohup python3 http_honeypot.py > /dev/null 2>&1 &

# MySQL honeypot (background)
nohup python3 mysql_honeypot.py > /dev/null 2>&1 &

# Dashboard (foreground or background)
python3 dashboard/app.py
```

### Running All Services (systemd)

See `deploy/honeynet.service` for a systemd unit file that manages all services together.

### Viewing Logs

```bash
# Live SSH event stream
tail -f logs/ssh_events.jsonl | python3 -m json.tool

# Count unique attacking IPs today
jq -r '.source_ip' logs/ssh_events.jsonl | sort -u | wc -l

# Top 10 usernames attempted
jq -r '.username' logs/ssh_events.jsonl | sort | uniq -c | sort -rn | head -10
```

---

## Log Format

Each service writes one JSON object per line to its respective `.jsonl` file.

**SSH event:**
```json
{
  "timestamp": "2026-05-01T14:22:03Z",
  "service": "ssh",
  "source_ip": "198.51.100.23",
  "source_port": 49201,
  "geo": {"country": "CN", "city": "Guangzhou", "asn": "AS4134"},
  "username": "root",
  "password": "admin123",
  "client_version": "SSH-2.0-libssh_0.9.6",
  "session_id": "a3f9c..."
}
```

**HTTP event:**
```json
{
  "timestamp": "2026-05-01T14:22:45Z",
  "service": "http",
  "source_ip": "203.0.113.77",
  "method": "POST",
  "path": "/wp-login.php",
  "user_agent": "Mozilla/5.0 (compatible; MJ12bot/v1.4.8)",
  "post_body": {"log": "admin", "pwd": "password1"},
  "geo": {"country": "RU", "city": "Moscow", "asn": "AS8359"},
  "session_id": "b7d2e..."
}
```

**MySQL event:**
```json
{
  "timestamp": "2026-05-01T14:23:10Z",
  "service": "mysql",
  "source_ip": "185.220.101.45",
  "client_version": "5.7.38",
  "username": "root",
  "auth_plugin": "mysql_native_password",
  "capabilities": 63487,
  "geo": {"country": "DE", "city": "Frankfurt", "asn": "AS396507"},
  "session_id": "c9a1f..."
}
```

---

## Dashboard

The built-in Flask dashboard at port 5000 provides:

- **Attack volume over time** (hourly and daily chart per service)
- **Top attacking IPs** with country flags and ASN labels
- **Credential frequency table** (SSH usernames and passwords ranked by attempt count)
- **HTTP path heatmap** (most-probed endpoints sorted by hit count)
- **Live event feed** (last 50 events across all services, auto-refreshing)
- **Geographic map** (attack origins plotted using Leaflet.js)

---

## Deployment (DigitalOcean)

**Recommended droplet:** Ubuntu 22.04, 1 vCPU / 1 GB RAM, any region

**Firewall rules to configure before launching:**

| Port | Protocol | Allow From | Purpose |
|---|---|---|---|
| 2222 | TCP | Any | SSH honeypot listener |
| 3306 | TCP | Any | MySQL honeypot listener |
| 8080 | TCP | Any | HTTP honeypot listener |
| 5000 | TCP | Your IP only | Dashboard (keep private) |
| 22 | TCP | Your IP only | Real SSH admin access |

**Setup steps:**

```bash
# On a fresh Ubuntu 22.04 droplet
sudo apt update && sudo apt install python3-pip python3-venv git -y
git clone https://github.com/Byrdsong-Portfolio/honeynet.git /opt/honeynet
cd /opt/honeynet
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo cp deploy/honeynet.service /etc/systemd/system/
sudo systemctl enable honeynet
sudo systemctl start honeynet
```

---

## Legal and Ethics

**This project is deployed on infrastructure I own and control. All captured data reflects unsolicited inbound connection attempts from external actors.**

- No active scanning, exploitation, or unauthorized access is performed by this system
- Captured credentials are stored locally and are not re-used or distributed
- IP addresses in logs are retained for research purposes only and are not shared publicly
- This project complies with applicable computer fraud and abuse statutes as a passive listener on owned infrastructure
- Do not deploy this system on infrastructure you do not own or have explicit authorization to run research tools on

---

## Requirements

```
paramiko>=3.4.0
flask>=3.0.0
flask-socketio>=5.3.0
geoip2>=4.7.0
requests>=2.31.0
python-dotenv>=1.0.0
```

---

*Built by Isaiah Byrdsong | [LinkedIn](https://www.linkedin.com/in/ibyrdsong/) | Cybersecurity and Intelligence Professional*
